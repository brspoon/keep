#!/usr/bin/env python3
"""Verify OCI source images, inventory notices and retain source/build inputs.

Source retention copies only designated material directories after verifying
every referenced OCI blob. It never extracts a container filesystem or follows
archive links. All original versions, directory/link metadata and whiteouts stay
in the retention manifest; bootstrap programs outside source paths are excluded.
"""
import argparse
from contextlib import contextmanager
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile


MANIFEST_TYPES = {
    'application/vnd.oci.image.manifest.v1+json',
    'application/vnd.docker.distribution.manifest.v2+json',
    'application/vnd.oci.artifact.manifest.v1+json',
}
INDEX_TYPES = {
    'application/vnd.oci.image.index.v1+json',
    'application/vnd.docker.distribution.manifest.list.v2+json',
}
NOTICE_NAME = re.compile(r'^(?:license|licence|copying[0-9]*|copyright|notice)(?:[._-]|$)', re.I)
ARCHIVE_SUFFIXES = ('.tar.gz', '.tgz', '.tar.xz', '.txz', '.tar.bz2', '.tbz2', '.tar', '.zip')
MATERIAL_DIRECTORIES = {'materials', 'git', 'context', 'def', 'provenance'}


class LimitedLayerReader:
    """Count decoded bytes, including skipped/trailing archive contents."""
    def __init__(self, stream, limit):
        self.stream, self.limit, self.consumed = stream, limit, 0

    def read(self, size=-1):
        if size < 0:
            raise ValueError('Layer reads must use a bounded size')
        try:
            body = self.stream.read(min(size, self.limit - self.consumed + 1))
        except ValueError:
            raise
        except Exception as error:
            raise ValueError('Source layer decompression failed') from error
        self.consumed += len(body)
        if self.consumed > self.limit:
            raise ValueError('Source layer decompressed byte limit exceeded')
        return body


class ModuleZstdReader:
    """Read zstandard frames incrementally and reject an unfinished last frame.

    zstandard's stream_reader can silently return EOF for truncated frames.
    Its decompression object exposes frame completion, including concatenated
    frames, so the bounded input/output checks can prove complete decoding.
    """
    def __init__(self, raw, module, limit):
        self.raw, self.limit = raw, limit
        self.decoder = module.ZstdDecompressor(max_window_size=128 * 1024 * 1024)
        self.frame = self.decoder.decompressobj()
        self.buffer = b''
        self.total = 0
        self.finished = False

    def read(self, size):
        while len(self.buffer) < size and not self.finished:
            data = self.raw.read(1024)
            if not data:
                if not self.frame.eof:
                    raise ValueError('Truncated Zstandard source layer frame')
                self.finished = True
                break
            while data:
                if self.frame.eof:
                    self.frame = self.decoder.decompressobj()
                body = self.frame.decompress(data)
                self.total += len(body)
                if self.total > self.limit:
                    raise ValueError('Source layer decompressed byte limit exceeded')
                self.buffer += body
                data = self.frame.unused_data if self.frame.eof else b''
        result, self.buffer = self.buffer[:size], self.buffer[size:]
        return result

    def close(self):
        self.buffer = b''


@contextmanager
def open_layer(path, media_type, *, max_bytes=8 * 1024 ** 3):
    """Open plain, gzip or Zstandard OCI tar layers with a decoded-byte bound.

    Python 3.14's optional standard decoder is preferred; older acquisition
    hosts can use zstandard or the system zstd command. No downloaded program
    runs, no shell is used, and the original verified blob is never modified.
    """
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError('Layer input must be a bounded regular file')
    if 'tar' not in media_type:
        raise ValueError('Unsupported source layer encoding')
    raw, decoded, process, completed = None, None, None, False
    try:
        raw = path.open('rb')
        if 'zstd' in media_type:
            try:
                from compression import zstd
            except ImportError:
                zstd = None
            if zstd is not None:
                decoded = zstd.open(raw, 'rb', options={zstd.DecompressionParameter.window_log_max: 27})
            else:
                try:
                    import zstandard
                except ImportError:
                    zstandard = None
                if zstandard is not None:
                    decoded = ModuleZstdReader(raw, zstandard, max_bytes)
                else:
                    executable = shutil.which('zstd')
                    if executable is None:
                        raise ValueError('Zstandard OCI layers require compression.zstd, zstandard or system zstd')
                    process = subprocess.Popen([executable, '-dc', '--no-progress', '--', str(path)],
                                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                    decoded = process.stdout
        elif media_type.endswith('+gzip') or media_type.endswith('.gzip'):
            decoded = gzip.GzipFile(fileobj=raw, mode='rb')
        elif media_type.endswith('.tar'):
            decoded = raw
        else:
            raise ValueError('Unsupported source layer encoding')
        reader = LimitedLayerReader(decoded, max_bytes)
        yield reader
        while reader.read(1024 * 1024):
            pass
        if process is not None and process.wait(timeout=10) != 0:
            raise ValueError('Zstandard OCI layer decompression failed')
        completed = True
    finally:
        if decoded is not None:
            decoded.close()
        if raw is not None:
            raw.close()
        if process is not None and not completed:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)


class PrefixReader:
    """Put a magic-detection prefix back without seeking the parent tar stream."""
    def __init__(self, prefix, stream):
        self.prefix = prefix
        self.stream = stream

    def read(self, size=-1):
        if size < 0:
            result, self.prefix = self.prefix, b''
            return result + self.stream.read()
        result, self.prefix = self.prefix[:size], self.prefix[size:]
        return result + self.stream.read(size - len(result))


def sha256(body):
    return hashlib.sha256(body).hexdigest()


def safe_name(name):
    """Reject ambiguous names even though no archive entry is extracted."""
    if (not isinstance(name, str) or not name or '\\' in name or '\x00' in name
            or name.startswith('/') or re.match(r'^[A-Za-z]:', name)
            or '..' in PurePosixPath(name).parts):
        raise ValueError('Unsafe archive member name')
    return str(PurePosixPath(name))


def is_notice(name):
    path = PurePosixPath(name)
    return bool(NOTICE_NAME.search(path.name) or any(
        part.lower() in {'licenses', 'licences'} for part in path.parts[:-1]))


def file_kind(name):
    base = PurePosixPath(name).name
    if is_notice(name):
        return 'notice'
    if name.lower().endswith(ARCHIVE_SUFFIXES):
        return 'source-archive'
    if (base == 'APKBUILD' or base.startswith('Dockerfile')
            or base in {'Makefile', 'meson.build', 'CMakeLists.txt', 'configure', 'configure.ac'}
            or base.endswith(('.patch', '.diff', '.yaml', '.yml'))):
        return 'build-input'
    return 'source-file'


class SourceInventory:
    def __init__(self, layout, output_dir, *, max_notice_bytes=4 * 1024 * 1024,
                 max_archive_bytes=512 * 1024 * 1024, max_depth=3,
                 max_members=250000, max_declared_bytes=8 * 1024 ** 3):
        self.layout = Path(layout)
        self.output_dir = Path(output_dir)
        self.max_notice_bytes = max_notice_bytes
        self.max_archive_bytes = max_archive_bytes
        self.max_depth = max_depth
        self.max_members = max_members
        self.max_declared_bytes = max_declared_bytes
        self.verified = {}
        self.visited = set()
        self.manifests = {}
        self.files = []
        self.notices = []
        self.warnings = []
        self.links_skipped = 0
        self.members = 0
        self.declared_bytes = 0
        self.limit_reached = False

    def warn(self, path, reason):
        self.warnings.append({'path': path, 'reason': reason})

    def blob(self, descriptor):
        """Verify the complete compressed blob before interpreting its bytes."""
        value = descriptor.get('digest')
        size = descriptor.get('size')
        if not isinstance(value, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', value):
            raise ValueError('Unsupported or malformed OCI blob digest')
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError('Malformed OCI blob size')
        path = self.layout / 'blobs' / 'sha256' / value.split(':', 1)[1]
        for component in (self.layout, self.layout / 'blobs', path.parent, path):
            if component.is_symlink():
                raise ValueError('OCI layout must not contain blob path symlinks')
        if not path.is_file():
            raise ValueError('Missing OCI blob')
        if value not in self.verified:
            hasher = hashlib.sha256()
            actual_size = 0
            with path.open('rb') as stream:
                while chunk := stream.read(1024 * 1024):
                    actual_size += len(chunk)
                    hasher.update(chunk)
            if value != 'sha256:' + hasher.hexdigest():
                raise ValueError('OCI blob digest mismatch')
            self.verified[value] = actual_size
        if self.verified[value] != size:
            raise ValueError('OCI descriptor size mismatch')
        return path

    def budget(self, path, size):
        self.members += 1
        self.declared_bytes += size
        if self.members > self.max_members or self.declared_bytes > self.max_declared_bytes:
            if not self.limit_reached:
                self.warn(path, 'Archive inventory limit reached; original OCI blobs are retained')
            self.limit_reached = True
            return False
        return True

    def regular_file(self, stream, name, size, origin, depth):
        location = origin + '!' + name
        kind = file_kind(name)
        zip_format = name.lower().endswith('.zip')
        if kind != 'notice':
            prefix = stream.read(min(size, 512))
            stream = PrefixReader(prefix, stream)
            zip_format = zip_format or prefix.startswith((b'PK\x03\x04', b'PK\x05\x06'))
            if (zip_format or prefix.startswith((b'\x1f\x8b', b'\xfd7zXZ\x00', b'BZh'))
                    or prefix[257:262] == b'ustar'):
                kind = 'source-archive'
        self.files.append({'path': location, 'bytes': size, 'kind': kind})
        if kind == 'notice':
            if size > self.max_notice_bytes:
                self.warn(location, 'Notice exceeds text-size limit; original bytes are retained')
                return
            body = stream.read(self.max_notice_bytes + 1)
            if len(body) != size:
                raise ValueError('Archive notice size mismatch')
            try:
                text = body.decode('utf-8')
                encoding = 'utf-8'
            except UnicodeDecodeError:
                # Older license texts may use Latin-1. Retain original bytes
                # rather than replacing or silently dropping attribution.
                text = body.decode('latin-1')
                encoding = 'latin-1'
            if b'\x00' in body or not text.strip():
                self.warn(location, 'Notice is empty or binary; original bytes are retained')
                return
            key = sha256(body)
            destination = self.output_dir / 'notices' / (key + '.txt')
            if self.output_dir.is_symlink() or destination.parent.is_symlink():
                raise ValueError('Notice destination must not be a symlink')
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.is_symlink():
                raise ValueError('Notice destination must not be a symlink')
            destination.write_bytes(body)
            self.notices.append({'path': location, 'bytes': size, 'sha256': key,
                                 'notice_file': 'notices/' + destination.name,
                                 'encoding': encoding})
        elif kind == 'source-archive':
            if depth >= self.max_depth:
                self.warn(location, 'Nested archive depth limit reached; original bytes are retained')
            elif size > self.max_archive_bytes:
                self.warn(location, 'Source archive exceeds scan-size limit; original bytes are retained')
            else:
                # ZIP needs seeking; spooling also bounds compressed input and
                # isolates nested tar readers from their parent stream.
                with tempfile.TemporaryFile() as nested:
                    remaining = size
                    while remaining:
                        chunk = stream.read(min(remaining, 1024 * 1024))
                        if not chunk:
                            raise ValueError('Truncated source archive')
                        nested.write(chunk)
                        remaining -= len(chunk)
                    nested.seek(0)
                    self.scan_archive(nested, location, depth + 1, zip_format=zip_format)

    def scan_archive(self, stream, origin, depth=0, zip_format=False):
        try:
            if zip_format:
                with zipfile.ZipFile(stream) as archive:
                    for member in archive.infolist():
                        name = safe_name(member.filename)
                        if not self.budget(origin + '!' + name, member.file_size):
                            break
                        if member.is_dir():
                            continue
                        if stat.S_ISLNK(member.external_attr >> 16):
                            self.links_skipped += 1
                            continue
                        if member.flag_bits & 1:
                            self.warn(origin + '!' + name, 'Encrypted ZIP entry cannot be inventoried')
                            continue
                        with archive.open(member) as content:
                            self.regular_file(content, name, member.file_size, origin, depth)
            else:
                # APK inputs concatenate signature, control and data tarballs
                # as separate gzip members. A seekable gzip reader processes
                # every member; ignore_zeros continues past each tar terminator.
                # Inputs here are verified blob files or bounded temporary files.
                with tarfile.open(fileobj=stream, mode='r:*', ignore_zeros=True) as archive:
                    for member in archive:
                        name = safe_name(member.name)
                        if not self.budget(origin + '!' + name, member.size):
                            break
                        if member.issym() or member.islnk():
                            self.links_skipped += 1
                        elif member.isfile():
                            with archive.extractfile(member) as content:
                                self.regular_file(content, name, member.size, origin, depth)
        except (tarfile.TarError, zipfile.BadZipFile, EOFError, OSError) as error:
            self.warn(origin, 'Archive cannot be fully inventoried: ' + type(error).__name__)

    def walk(self, descriptor):
        path = self.blob(descriptor)
        value = descriptor['digest']
        if value in self.visited:
            return
        self.visited.add(value)
        if descriptor.get('mediaType') not in MANIFEST_TYPES | INDEX_TYPES:
            raise ValueError('Unexpected OCI manifest media type')
        if path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError('OCI manifest exceeds size limit')
        manifest = json.loads(path.read_bytes())
        self.manifests[value] = manifest
        if manifest.get('schemaVersion', 2) != 2:
            raise ValueError('Unsupported OCI manifest schema')
        if descriptor['mediaType'] in INDEX_TYPES:
            for child in manifest.get('manifests', []):
                self.walk(child)
            return
        if manifest.get('config') is not None:
            self.blob(manifest['config'])
        for layer in manifest.get('layers', manifest.get('blobs', [])):
            self.blob(layer)

    def inventory_manifest(self, value, visited=None):
        visited = set() if visited is None else visited
        if value in visited:
            return
        visited.add(value)
        manifest = self.manifests[value]
        for child in manifest.get('manifests', []):
            self.inventory_manifest(child['digest'], visited)
        for layer in manifest.get('layers', manifest.get('blobs', [])):
            blob = self.blob(layer)
            media_type = layer.get('mediaType', '')
            if 'tar' in media_type:
                # Nested ZIP and concatenated APK payloads need seeking. Spool
                # only decoded bytes after the bounded layer decoder checks them.
                with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as decoded:
                    with open_layer(blob, media_type, max_bytes=self.max_declared_bytes) as stream:
                        while chunk := stream.read(1024 * 1024):
                            decoded.write(chunk)
                    decoded.seek(0)
                    self.scan_archive(decoded, layer['digest'])
            else:
                self.warn(layer['digest'], 'Non-tar or unsupported layer retained without notice scanning')

    def bind(self, expected_digest):
        """Verify layout reachability and bytes before interpreting source files."""
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', expected_digest):
            raise ValueError('Malformed expected source-image digest')
        if self.layout.is_symlink() or (self.layout / 'index.json').is_symlink():
            raise ValueError('OCI layout/index must not be a symlink')
        if self.output_dir.resolve().is_relative_to(self.layout.resolve()):
            raise ValueError('Notice output must be outside the retained OCI layout')
        marker = self.layout / 'oci-layout'
        if marker.is_symlink() or json.loads(marker.read_text()).get('imageLayoutVersion') != '1.0.0':
            raise ValueError('Unsupported OCI layout version')
        index = json.loads((self.layout / 'index.json').read_text())
        if index.get('schemaVersion') != 2 or not index.get('manifests'):
            raise ValueError('Malformed OCI layout index')
        for descriptor in index['manifests']:
            self.walk(descriptor)
        # regctl can retain the source manifest directly or wrap it in an OCI
        # index. The attested digest must still be a reachable, verified root.
        if expected_digest not in self.visited:
            raise ValueError('Expected source-image root digest is not present in the OCI layout')

    def inspect(self, expected_digest):
        self.bind(expected_digest)
        self.inventory_manifest(expected_digest)
        if not self.notices:
            self.warn(expected_digest, 'No readable license notices found; inspect retained sources before claiming coverage')
        return {
            'source_image_digest': expected_digest,
            'binding_verified': True,
            'verified_blobs': [{'digest': value, 'bytes': size} for value, size in sorted(self.verified.items())],
            'files': self.files,
            'notices': self.notices,
            'warnings': self.warnings,
            'links_skipped': self.links_skipped,
            'notice_inventory_complete': not self.warnings,
            'limitations': 'All original OCI materials retained. Links are not followed; notice discovery uses filenames and bounded nested archives, not legal coverage certification.',
        }


def inspect_layout(layout, expected_digest, output_dir, **limits):
    return SourceInventory(layout, output_dir, **limits).inspect(expected_digest)


def retain_materials(layout, expected_digest, output_dir, *, max_members=250000,
                     max_retained_bytes=8 * 1024 ** 3):
    """Copy all regular source-path files; record links without following them.

Files are stored by manifest/layer ordinal and original member path, preserving
overwritten versions instead of interpreting a container root filesystem.
Archive member links, original modes and whiteouts are recorded as data for
source reconstruction. No downloaded command or build recipe is executed.
"""
    output = Path(output_dir)
    verifier = SourceInventory(layout, output)
    verifier.bind(expected_digest)
    if output.is_symlink() or output.exists() and any(output.iterdir()):
        raise ValueError('Material output must be an empty directory without symlinks')
    output.mkdir(parents=True, exist_ok=True)
    records = []
    visited = set()
    retained_bytes = 0
    member_count = 0

    def target_for(relative):
        path = output / relative
        parent = output
        for part in PurePosixPath(relative).parts[:-1]:
            parent = parent / part
            if parent.is_symlink():
                raise ValueError('Material destination must not contain symlinks')
            parent.mkdir(exist_ok=True)
        if path.is_symlink() or path.exists():
            raise ValueError('Duplicate or unsafe material destination')
        return path

    def walk(value):
        nonlocal retained_bytes, member_count
        if value in visited:
            return
        visited.add(value)
        manifest = verifier.manifests[value]
        for child in manifest.get('manifests', []):
            walk(child['digest'])
        # Referrer attestations are verified but are not source filesystems.
        if manifest.get('artifactType'):
            return
        for number, descriptor in enumerate(manifest.get('layers', [])):
            media_type = descriptor.get('mediaType', '')
            if 'tar' not in media_type:
                raise ValueError('Unsupported source material layer encoding')
            blob = verifier.blob(descriptor)
            names = set()
            with open_layer(blob, media_type, max_bytes=max_retained_bytes) as stream, tarfile.open(fileobj=stream, mode='r|*') as archive:
                for member in archive:
                    member_count += 1
                    if member_count > max_members:
                        raise ValueError('Source material member limit exceeded')
                    name = safe_name(member.name)
                    parts = PurePosixPath(name).parts
                    if len(parts) < 3 or parts[:2] != ('opt', 'docker') or parts[2] not in MATERIAL_DIRECTORIES:
                        continue
                    if name in names:
                        raise ValueError('Duplicate source material archive member')
                    names.add(name)
                    record = {'manifest_digest': value, 'layer_digest': descriptor['digest'],
                              'layer': number, 'source_path': name,
                              'mode': member.mode, 'mtime': member.mtime}
                    base = parts[-1]
                    if base.startswith('.wh.'):
                        if not member.isfile() or member.size:
                            raise ValueError('Malformed source material whiteout')
                        records.append({**record, 'type': 'whiteout',
                                        'opaque': base == '.wh..wh..opq'})
                    elif member.isdir():
                        records.append({**record, 'type': 'directory'})
                    elif member.issym() or member.islnk():
                        if not isinstance(member.linkname, str) or '\x00' in member.linkname:
                            raise ValueError('Malformed source material link target')
                        records.append({**record, 'type': 'symlink' if member.issym() else 'hardlink',
                                        'target': member.linkname,
                                        'target_sha256': sha256(member.linkname.encode('utf-8'))})
                    elif member.isfile():
                        retained_bytes += member.size
                        if retained_bytes > max_retained_bytes:
                            raise ValueError('Source material byte limit exceeded')
                        relative = f'files/{value.split(":", 1)[1]}/layers/{number}/{name}'
                        destination = target_for(relative)
                        hasher = hashlib.sha256()
                        copied = 0
                        with archive.extractfile(member) as source, destination.open('xb') as target:
                            while chunk := source.read(1024 * 1024):
                                target.write(chunk)
                                hasher.update(chunk)
                                copied += len(chunk)
                        if copied != member.size:
                            raise ValueError('Truncated source material archive member')
                        # Retain executable scripts without applying set-ID bits.
                        destination.chmod(0o755 if member.mode & 0o111 else 0o644)
                        records.append({**record, 'type': 'file', 'path': relative,
                                        'bytes': copied, 'sha256': hasher.hexdigest()})
                    else:
                        raise ValueError('Unsupported source material entry type')

    walk(expected_digest)
    if not any(record['type'] == 'file' for record in records):
        raise ValueError('No source/build material files found')
    manifest = {'schema': 1, 'source_image_digest': expected_digest, 'binding_verified': True,
                'verified_blobs': [{'digest': value, 'bytes': size}
                                   for value, size in sorted(verifier.verified.items())],
                'files': records, 'retained_bytes': retained_bytes,
                'source_directories': sorted(MATERIAL_DIRECTORIES),
                'limitations': 'Retains designated source/build paths only. Directory/link/whiteout metadata is preserved without following links or replaying filesystem layers. Does not certify corresponding-source or license coverage.'}
    (output / 'material-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--layout', required=True)
    parser.add_argument('--digest', required=True)
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--report')
    args = parser.parse_args()
    result = inspect_layout(args.layout, args.digest, args.output_dir)
    rendered = json.dumps(result, indent=2) + '\n'
    if args.report:
        Path(args.report).write_text(rendered)
    else:
        print(rendered, end='')


if __name__ == '__main__':
    main()
