"""Matching database, configuration, and image recovery-set verification.

Reads private adapter-selected files without archive extraction or Docker access.
"""
from __future__ import annotations

import hashlib
import gzip
import io
import json
from pathlib import Path, PurePosixPath
import re
import sqlite3
import tarfile
import time
import zlib

from maintenance_protocol import ImageIdentity, canonical, canonical_uuid, parse_json
from private_store import StorageError

MAX_IMAGE = 32 * 1024**3
MAX_DATABASE = 4 * 1024**3
MAX_CONFIG = 1048576
SHA256 = re.compile(r'sha256:[a-f0-9]{64}\Z')
OCI_INDEX = ('application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json')
OCI_MANIFEST = ('application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json')
OCI_CONFIG = ('application/vnd.oci.image.config.v1+json','application/vnd.docker.container.image.v1+json')
RAW_LAYERS = ('application/vnd.oci.image.layer.v1.tar','application/vnd.docker.image.rootfs.diff.tar')
GZIP_LAYERS = ('application/vnd.oci.image.layer.v1.tar+gzip','application/vnd.docker.image.rootfs.diff.tar.gzip')


def file_digest(paths, path, *, limit):
    path = paths.check(path)
    if path.stat().st_size > limit:
        raise StorageError("Recovery artifact exceeds its size limit")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while data := stream.read(1048576):
            size += len(data)
            if size > limit:
                raise StorageError("Recovery artifact exceeds its size limit")
            digest.update(data)
    return {"sha256": digest.hexdigest(), "bytes": size}


def sqlite_identity(paths, path):
    path = paths.check(path)
    if path.stat().st_size > MAX_DATABASE:
        raise StorageError("Recovery database exceeds its size limit")
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5) as db:
        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise StorageError("Recovery database integrity check failed")
        user_version = db.execute("PRAGMA user_version").fetchone()[0]
    return {**file_digest(paths, path, limit=MAX_DATABASE), "user_version": user_version}


def verify_docker_save(paths, path, identity):
    """Verify classic or complete original-index OCI save bytes without extraction.

    OCI/gzip support is a verifier contract, not native Docker qualification.
    Missing original indexes and unsupported compression always hold recovery.
    """
    identity = ImageIdentity.from_dict(identity.as_dict())
    archive_identity = file_digest(paths, path, limit=MAX_IMAGE)
    members = {}
    with tarfile.open(path, mode="r:") as archive:
        for member in archive:
            parts = PurePosixPath(member.name)
            if (parts.is_absolute() or ".." in parts.parts or member.name in members
                    or not (member.isfile() or member.isdir()) or member.size > MAX_IMAGE):
                raise StorageError("Image archive contains an unsafe member")
            if len(members) >= 4096:
                raise StorageError("Image archive contains too many members")
            members[member.name] = member

        def small(name):
            member = members.get(name)
            if not member or not member.isfile() or member.size > 65536:
                raise StorageError("Image archive metadata is unavailable")
            stream = archive.extractfile(member)
            if stream is None:
                raise StorageError("Image archive metadata is unavailable")
            return stream.read(65537)

        def configuration(data):
            config=parse_json(data,65536)
            if not isinstance(config,dict) or not isinstance(config.get('config'),dict):
                raise StorageError('Recovery image configuration is invalid')
            labels=config['config'].get('Labels')
            rootfs=config.get('rootfs')
            if (not isinstance(labels,dict) or not isinstance(rootfs,dict)
                    or config.get('architecture')!=identity.architecture or config.get('os')!='linux'
                    or labels.get('org.opencontainers.image.version')!=identity.version
                    or labels.get('org.opencontainers.image.revision')!=identity.revision
                    or labels.get('org.opencontainers.image.source')!='https://github.com/brspoon/keep'
                    or config['config'].get('User')!='10001:10001'
                    or rootfs.get('type')!='layers' or not isinstance(rootfs.get('diff_ids'),list)
                    or not 1<=len(rootfs['diff_ids'])<=128 or any(not isinstance(value,str)
                        or not SHA256.fullmatch(value) for value in rootfs['diff_ids'])):
                raise StorageError('Recovery image metadata does not match')
            return config

        def descriptor(value,types):
            if (not isinstance(value,dict) or not {'mediaType','digest','size'}<=set(value)
                    or not set(value)<={'mediaType','digest','size','platform','annotations','artifactType'}
                    or value['mediaType'] not in types or not isinstance(value['digest'],str)
                    or not SHA256.fullmatch(value['digest']) or type(value['size']) is not int
                    or not 0<=value['size']<=MAX_IMAGE):
                raise StorageError('Recovery OCI descriptor is invalid')
            annotations=value.get('annotations',{})
            if not isinstance(annotations,dict) or len(annotations)>32 or any(not isinstance(key,str)
                    or not isinstance(text,str) or len(key)>256 or len(text)>4096 for key,text in annotations.items()):
                raise StorageError('Recovery OCI annotations are invalid')
            references={identity.reference,'docker.io/'+identity.reference,'brspoon/keep:'+identity.version,
                'docker.io/brspoon/keep:'+identity.version,identity.version}
            if any(annotations.get(field) not in references for field in
                    ('io.containerd.image.name','org.opencontainers.image.ref.name') if field in annotations):
                raise StorageError('Recovery archive names an unrelated image')
            return 'blobs/sha256/'+value['digest'][7:]

        def blob(value,types):
            name=descriptor(value,types);data=small(name)
            if len(data)!=value['size'] or 'sha256:'+hashlib.sha256(data).hexdigest()!=value['digest']:
                raise StorageError('Recovery OCI metadata bytes do not match')
            return parse_json(data,65536),name,data

        def tags(value):
            if value is None:return
            allowed={'brspoon/keep:'+identity.version,identity.reference,'brspoon/keep@'+identity.native_digest}
            allowed|={'docker.io/'+reference for reference in tuple(allowed)}
            if not isinstance(value,list) or len(value)>8 or any(not isinstance(tag,str) or tag not in allowed for tag in value):
                raise StorageError('Recovery archive contains an unrelated repository name')

        if 'oci-layout' in members or 'index.json' in members:
            if parse_json(small('oci-layout'),65536)!={'imageLayoutVersion':'1.0.0'}:
                raise StorageError('Recovery OCI layout is unsupported')
            top=parse_json(small('index.json'),65536)
            if (not isinstance(top,dict) or top.get('schemaVersion')!=2 or top.get('mediaType') not in OCI_INDEX
                    or not isinstance(top.get('manifests'),list) or len(top['manifests'])!=1):
                raise StorageError('Recovery OCI export must contain one original index')
            root=top['manifests'][0]
            index,_,_=blob(root,OCI_INDEX)
            if (root['digest']!=identity.index_digest or not isinstance(index,dict) or index.get('schemaVersion')!=2
                    or index.get('mediaType') not in OCI_INDEX or not isinstance(index.get('manifests'),list)
                    or not 1<=len(index['manifests'])<=16):
                raise StorageError('Recovery archive does not retain the original index')
            matches=[]
            for entry in index['manifests']:
                descriptor(entry,OCI_MANIFEST+OCI_INDEX)
                platform=entry.get('platform')
                if isinstance(platform,dict) and platform.get('os')=='linux' and platform.get('architecture')==identity.architecture:
                    matches.append(entry)
            if len(matches)!=1 or matches[0]['digest']!=identity.native_digest:
                raise StorageError('Recovery native manifest does not match the original index')
            native,_,_=blob(matches[0],OCI_MANIFEST)
            if (not isinstance(native,dict) or native.get('schemaVersion')!=2 or native.get('mediaType') not in OCI_MANIFEST
                    or not isinstance(native.get('config'),dict) or native['config'].get('digest')!=identity.image_id):
                raise StorageError('Recovery native configuration does not match')
            _,config_name,config_data=blob(native['config'],OCI_CONFIG)
            config=configuration(config_data);layers=native.get('layers');diffs=config['rootfs']['diff_ids']
            if not isinstance(layers,list) or len(layers)!=len(diffs):
                raise StorageError('Recovery native layers are incomplete')
            names=[descriptor(value,RAW_LAYERS+GZIP_LAYERS) for value in layers]
            if len(set(names))!=len(names):raise StorageError('Recovery native layers are duplicated')
            if 'manifest.json' in members:
                compatible=parse_json(small('manifest.json'),65536)
                if (not isinstance(compatible,list) or len(compatible)!=1 or not isinstance(compatible[0],dict)
                        or set(compatible[0])!={'Config','RepoTags','Layers'} or compatible[0]['Config']!=config_name
                        or compatible[0]['Layers']!=names):
                    raise StorageError('Docker and OCI archive metadata differ')
                tags(compatible[0]['RepoTags'])
            # Every retained blob has an exact name/content binding, including
            # any available other-platform children. No filesystem extraction.
            deadline=time.monotonic()+300
            for name,member in members.items():
                if member.isdir():continue
                if name in ('index.json','oci-layout','manifest.json'):continue
                if not re.fullmatch(r'blobs/sha256/[a-f0-9]{64}',name):
                    raise StorageError('Recovery OCI archive contains an unsupported member')
                digest=hashlib.sha256();stream=archive.extractfile(member)
                while data:=stream.read(1048576):
                    if time.monotonic()>deadline:raise StorageError('Recovery archive verification exceeded its bound')
                    digest.update(data)
                if digest.hexdigest()!=name.rsplit('/',1)[1]:raise StorageError('Recovery OCI blob content changed')
            total=0
            for value,name,expected in zip(layers,names,diffs):
                member=members.get(name)
                if not member or not member.isfile() or member.size!=value['size']:
                    raise StorageError('Recovery native layer size does not match')
                stream=archive.extractfile(member)
                if value['mediaType'] in GZIP_LAYERS:stream=gzip.GzipFile(fileobj=stream,mode='rb')
                digest=hashlib.sha256()
                try:
                    while data:=stream.read(1048576):
                        total+=len(data)
                        if total>MAX_IMAGE or time.monotonic()>deadline:
                            raise StorageError('Recovery decompression exceeded its bound')
                        digest.update(data)
                except (OSError,EOFError,zlib.error) as error:raise StorageError('Recovery layer compression is invalid') from error
                finally:stream.close()
                if 'sha256:'+digest.hexdigest()!=expected:raise StorageError('Recovery uncompressed layer differs from configuration')
            return archive_identity

        manifest = parse_json(small("manifest.json"), 65536)
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise StorageError("Recovery image archive must contain one image")
        entry = manifest[0]
        if not isinstance(entry, dict) or set(entry) != {"Config", "RepoTags", "Layers"}:
            raise StorageError("Recovery image manifest has unsupported fields")
        config_name = entry["Config"]
        if not isinstance(config_name, str) or not re.fullmatch(r"(?:[a-f0-9]{64}\.json|blobs/sha256/[a-f0-9]{64})", config_name):
            raise StorageError("Recovery image configuration identity is invalid")
        config_bytes = small(config_name)
        if "sha256:" + hashlib.sha256(config_bytes).hexdigest() != identity.image_id:
            raise StorageError("Recovery image configuration does not match")
        config = configuration(config_bytes)
        tags(entry['RepoTags'])
        layers = entry["Layers"]
        diffs = config.get("rootfs", {}).get("diff_ids")
        if (not isinstance(layers, list) or not 1 <= len(layers) <= 128
                or len(set(layers)) != len(layers) or not isinstance(diffs, list) or len(diffs) != len(layers)):
            raise StorageError("Recovery image layers are incomplete")
        for name, expected in zip(layers, diffs):
            if not isinstance(name, str) or name not in members or not members[name].isfile():
                raise StorageError("Recovery image layer is unavailable")
            digest = hashlib.sha256()
            stream = archive.extractfile(members[name])
            if stream is None:
                raise StorageError("Recovery image layer is unavailable")
            while data := stream.read(1048576):
                digest.update(data)
            if "sha256:" + digest.hexdigest() != expected:
                raise StorageError("Recovery image layer does not match")
    return archive_identity


class RecoverySet:
    """A seal becomes usable only after matching artifacts are fully verified.

Artifacts must already be exported into this private host directory by the
quiescent fixed-volume adapter. Sealing never substitutes for stop/drain proof.
The immutable manifest must not be reused with another operation/config/image.
"""
    def __init__(self, paths, root, request_id):
        self.paths, self.root = paths, Path(root)
        self.request_id = canonical_uuid(request_id)
        paths.check(self.root, directory=True)

    def seal(self, previous, configuration_names, *, daemon_id, project, volume):
        if (not 1 <= len(configuration_names) <= 6 or len(set(configuration_names)) != len(configuration_names)
                or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", name) for name in configuration_names)):
            raise StorageError("Invalid enrolled recovery configuration")
        previous = ImageIdentity.from_dict(previous.as_dict())
        value = {"schema": "keep.recovery-set.v1", "request_id": self.request_id,
                 "daemon_id": daemon_id, "project": project, "volume": volume,
                 "image": previous.as_dict(), "database": sqlite_identity(self.paths, self.root / "database.sqlite3"),
                 "archive": verify_docker_save(self.paths, self.root / "image.tar", previous),
                 "configuration": [{"name": name, **file_digest(self.paths, self.root / f"config-{index}", limit=MAX_CONFIG)}
                                   for index, name in enumerate(configuration_names)]}
        self.paths.publish(self.root / "manifest.json", canonical(value))
        return value

    def verify(self, expected_manifest):
        manifest = parse_json(self.paths.read(self.root / "manifest.json"), 65536)
        if manifest != expected_manifest or manifest["request_id"] != self.request_id:
            raise StorageError("Recovery seal identity changed")
        previous = ImageIdentity.from_dict(manifest["image"])
        if sqlite_identity(self.paths, self.root / "database.sqlite3") != manifest["database"]:
            raise StorageError("Recovery database changed")
        if verify_docker_save(self.paths, self.root / "image.tar", previous) != manifest["archive"]:
            raise StorageError("Recovery image archive changed")
        for index, config in enumerate(manifest["configuration"]):
            if file_digest(self.paths, self.root / f"config-{index}", limit=MAX_CONFIG) != {key: config[key] for key in ("sha256", "bytes")}:
                raise StorageError("Recovery configuration changed")
        return previous

    def restoration_plan(self, expected_manifest, *, current_stop_proof):
        """All artifacts verified before any restore; plan contains fixed slots.

This produces no mutations. The adapter must preserve current DB/WAL/SHM,
configuration and image records before restoring, and keep both services stopped
until all three components have been restored and independently verified.
"""
        expected = self.verify(expected_manifest)
        required = {"daemon_id": expected_manifest["daemon_id"], "project": expected_manifest["project"],
                    "volume": expected_manifest["volume"], "services": {"keep-app": "stopped", "keep-digest": "stopped"}}
        if current_stop_proof != required:
            raise StorageError("Matching stopped-service proof is required")
        return {"database_slot": "database.sqlite3", "configuration_slots": tuple(
                    f"config-{index}" for index in range(len(expected_manifest["configuration"]))),
                "archive_slot": "image.tar", "image": expected.as_dict(),
                "preserve_failed_database_sidecars": True, "preserve_all_recovery_files": True}
