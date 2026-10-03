#!/usr/bin/env python3
"""Install Keep's Docker services, or prepare their private configuration."""

import argparse
import ipaddress
import json
import os
import re
import secrets
import stat
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

if os.name == "nt":
    import msvcrt
else:
    import fcntl


ENV_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")
SECRET_RE = re.compile(r"^[\x21-\x7e]{32,4096}$")
IMAGE_RE = re.compile(
    r"^(?:[A-Za-z0-9._-]+(?::[0-9]+)?/)?[A-Za-z0-9._/-]+"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}|@sha256:[a-fA-F0-9]{64})$"
)
RELEASE_VERSION = "2.21.2"
RELEASE_BASE = f"https://raw.githubusercontent.com/brspoon/keep/{RELEASE_VERSION}/"
MANAGED_KEYS = ("KEEP_URL", "FLASK_SECRET_KEY", "KEEP_WEBHOOK_SECRET", "KEEP_IMAGE",
                "KEEP_TRANSPORT_MODE", "KEEP_BIND_ADDRESS", "KEEP_PORT")
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(network) for network in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"))


class InstallError(Exception):
    """An unsafe or invalid local installation configuration."""


WINDOWS_ACL_CHECK = r"""
$ErrorActionPreference = 'Stop'
$path = $env:KEEP_INSTALL_ACL_PATH
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$allowed = @($current.Value, 'S-1-5-18', 'S-1-5-32-544')
$item = Get-Item -LiteralPath $path -Force
$ancestor = $item
while ($null -ne $ancestor) {
    if (($ancestor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Reparse points are not permitted in installation paths'
    }
    $ancestor = if ($ancestor -is [System.IO.DirectoryInfo]) { $ancestor.Parent } else { $ancestor.Directory }
}
if ($env:KEEP_INSTALL_ACL_ACTION -eq 'protect') {
    $acl = if ($item -is [System.IO.DirectoryInfo]) {
        New-Object System.Security.AccessControl.DirectorySecurity
    } else { New-Object System.Security.AccessControl.FileSecurity }
    $acl.SetOwner($current)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sidText in $allowed) {
        $sid = [System.Security.Principal.SecurityIdentifier]::new($sidText)
        $inherit = if ($item -is [System.IO.DirectoryInfo]) {
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        } else { [System.Security.AccessControl.InheritanceFlags]::None }
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $path -AclObject $acl
}
$acl = Get-Acl -LiteralPath $path
$owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ($owner -ne $current.Value) { throw 'Installation paths must belong to the current user' }
$hasAccess = $false
foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
        if ($allowed -notcontains $rule.IdentityReference.Value) { throw 'Installation ACL allows another identity' }
        if ($rule.IdentityReference.Value -eq $current.Value -and
            ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq
            [System.Security.AccessControl.FileSystemRights]::FullControl) { $hasAccess = $true }
    }
}
if (-not $hasAccess) { throw 'Installation ACL must allow the current user full control' }
"""


def _windows_private_acl(path, *, protect=False):
    environment = {**os.environ, "KEEP_INSTALL_ACL_PATH": str(Path(path).absolute()),
                   "KEEP_INSTALL_ACL_ACTION": "protect" if protect else "check"}
    try:
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_ACL_CHECK],
                                env=environment, capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise InstallError("could not verify private Windows file permissions; PowerShell is required") from error
    if result.returncode:
        raise InstallError("Windows installation paths must be private, owned by this user, and contain no junctions or reparse points")


def _posix_trusted_directory_chain(path, symlinks=None):
    """Trust directory entries only when another local identity cannot replace them.

    Sticky temporary directories protect entries owned by this user or root.
    Symlink targets are checked as written, before resolving the canonical path,
    so another link or writable parent in a target cannot disappear from review.
    """
    # Keep '..' until each preceding symlink has been checked. Lexical abspath
    # would erase a link even though filesystem traversal follows its target.
    path = Path(path).absolute()
    symlinks = set() if symlinks is None else symlinks
    trusted_owners = {0, os.getuid()}
    current = Path(path.anchor)
    for component in (None, *path.parts[1:]):
        if component is not None:
            current /= component
        try:
            info = current.lstat()
        except OSError as error:
            raise InstallError("installation path ancestors must be existing trusted directories") from error
        if info.st_uid not in trusted_owners:
            raise InstallError("installation path ancestors must be owned by this user or root")
        if stat.S_ISLNK(info.st_mode):
            identity = str(current)
            if identity in symlinks or len(symlinks) >= 40:
                raise InstallError("installation path contains a symlink loop")
            target = Path(os.readlink(current))
            if not target.is_absolute():
                target = current.parent / target
            _posix_trusted_directory_chain(target, symlinks | {identity})
        elif not stat.S_ISDIR(info.st_mode):
            raise InstallError("installation path ancestors must be directories")
        elif info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise InstallError("installation path ancestors writable by others must have the sticky bit")


def _posix_trusted_ancestors(path):
    original = Path(path).absolute()
    _posix_trusted_directory_chain(original)
    try:
        canonical = original.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise InstallError("installation path could not be safely resolved") from error
    _posix_trusted_directory_chain(canonical)


def _private_parent(path):
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise InstallError(f"configuration directory does not exist: {path}") from error
    if not stat.S_ISDIR(info.st_mode):
        raise InstallError("configuration directory must be a regular directory")
    if os.name == "nt":
        _windows_private_acl(path)
    elif info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise InstallError("configuration directory must be owned by this user and not writable by others")
    else:
        _posix_trusted_ancestors(path)


def _protect_created_file(fd, path):
    if os.name == "nt":
        _windows_private_acl(path, protect=True)
    else:
        os.fchmod(fd, 0o600)


def validate_bind_address(value):
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError) as error:
        raise InstallError("--bind-address must be a private or loopback IPv4 address") from error
    if not any(address in network for network in PRIVATE_NETWORKS):
        raise InstallError("--bind-address must be a private or loopback IPv4 address")
    return str(address)


def validate_port(value):
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,5}", str(value)):
        raise InstallError("--port must be a number between 1 and 65535")
    port = int(value)
    if not 1 <= port <= 65535:
        raise InstallError("--port must be a number between 1 and 65535")
    return port


def validate_url(value, transport_mode="https"):
    if transport_mode not in ("https", "lan-http"):
        raise InstallError("KEEP_TRANSPORT_MODE must be https or lan-http")
    expected_scheme = "https" if transport_mode == "https" else "http"
    description = "HTTPS origin" if transport_mode == "https" else "private IPv4 HTTP origin"
    if not isinstance(value, str) or not value or value != value.strip():
        raise InstallError(f"--url must be an {description}")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise InstallError(f"--url must be an {description}") from error
    if (parsed.scheme.lower() != expected_scheme or not parsed.hostname or
            parsed.username is not None or parsed.password is not None or
            parsed.query or parsed.fragment or parsed.path not in ("", "/") or
            any(char.isspace() or ord(char) < 32 for char in value)):
        raise InstallError(f"--url must contain only an {description}")
    if port is not None and not 1 <= port <= 65535:
        raise InstallError("--url has an invalid port")
    host = parsed.hostname
    if transport_mode == "lan-http":
        validate_bind_address(host)
    try:
        host.encode("idna")
    except UnicodeError as error:
        raise InstallError("--url has an invalid hostname") from error
    if "/" in host or not re.fullmatch(r"[A-Za-z0-9.:-]+", host):
        raise InstallError("--url has an invalid hostname")
    # A trailing slash denotes the same origin; store a canonical origin.
    authority = parsed.netloc
    return f"{expected_scheme}://{authority}".rstrip("/")


def validate_image(value):
    if not value or value != value.strip() or not IMAGE_RE.fullmatch(value):
        raise InstallError("KEEP_IMAGE must be an image tag or sha256 digest reference")
    return value


def _check_regular(path, *, missing_ok):
    try:
        info = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return None
        raise InstallError(f"required local file is missing: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise InstallError(f"refusing non-regular file: {path}")
    if os.name == "nt":
        _windows_private_acl(path)
    return info


def _read_env(path):
    info = _check_regular(path, missing_ok=True)
    if info is None:
        return [], {}
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise InstallError(f"cannot safely open {path}: {error.strerror}") from error
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise InstallError(f"refusing non-regular file: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read()
    finally:
        os.close(fd)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InstallError(".env must be UTF-8 text") from error
    # splitlines(keepends=True) preserves untouched bytes after UTF-8 decoding.
    lines = text.splitlines(keepends=True)
    values = {}
    for index, line in enumerate(lines):
        match = ENV_RE.match(line.rstrip("\r\n"))
        if not match:
            continue
        key = match.group(1)
        if key in MANAGED_KEYS:
            if key in values:
                raise InstallError(f".env contains duplicate {key} entries")
            raw_value = line.rstrip("\r\n")[match.end():]
            # This installer emits unquoted values; preserve existing values only
            # when they are plain dotenv values without interpolation/comment syntax.
            value = raw_value.strip()
            if value.startswith("'") and value.endswith("'") and len(value) >= 2:
                value = value[1:-1]
            elif value.startswith('"') and value.endswith('"') and len(value) >= 2:
                value = value[1:-1]
            else:
                value = value.split(" #", 1)[0].rstrip()
            values[key] = (index, value)
    return lines, values


def _secure_lock(path):
    lock_path = path.with_name(path.name + ".install.lock")
    existed = _check_regular(lock_path, missing_ok=True) is not None
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError as error:
        raise InstallError(f"cannot safely open installer lock: {error.strerror}") from error
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise InstallError("refusing non-regular installer lock")
    try:
        if os.name == "nt":
            if not existed:
                _windows_private_acl(lock_path, protect=True)
            if not os.fstat(fd).st_size:
                os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
    except Exception:
        os.close(fd)
        raise
    return fd


def install(env_path, requested_url, requested_image=None, *, transport_mode=None,
            bind_address=None, port=None):
    path = Path(env_path)
    parent = path.parent
    _private_parent(parent)
    mode = transport_mode or "https"
    url = validate_url(requested_url, mode)
    if bind_address is not None:
        bind_address = validate_bind_address(bind_address)
    if port is not None:
        port = validate_port(port)
    if mode == "lan-http" and bind_address is not None:
        parsed = urlsplit(url)
        if parsed.hostname != bind_address or (parsed.port or 80) != (port or 5000):
            raise InstallError("LAN HTTP URL must match the selected bind address and port")
    if requested_image is not None:
        requested_image = validate_image(requested_image)
    lock_fd = _secure_lock(path)
    try:
        _check_regular(path, missing_ok=True)
        lines, current = _read_env(path)
        existing_url = current.get("KEEP_URL", (None, ""))[1]
        if existing_url:
            try:
                old_url = validate_url(existing_url, current.get("KEEP_TRANSPORT_MODE", (None, "https"))[1])
            except InstallError as error:
                raise InstallError("existing KEEP_URL is invalid; refusing to replace it") from error
            if old_url != url:
                raise InstallError("existing KEEP_URL conflicts with --url; edit it explicitly first")

        chosen_image = current.get("KEEP_IMAGE", (None, ""))[1]
        if requested_image and chosen_image and validate_image(chosen_image) != requested_image:
            raise InstallError("existing KEEP_IMAGE conflicts with --image; edit it explicitly first")
        if requested_image:
            chosen_image = requested_image
        elif chosen_image:
            chosen_image = validate_image(chosen_image)

        updates = {}
        if not existing_url:
            updates["KEEP_URL"] = url
        for name in ("FLASK_SECRET_KEY", "KEEP_WEBHOOK_SECRET"):
            existing = current.get(name, (None, ""))[1]
            if existing:
                if not SECRET_RE.fullmatch(existing):
                    raise InstallError(f"existing {name} is not a valid generated secret; refusing to replace it")
            else:
                updates[name] = secrets.token_urlsafe(48)
        if requested_image and not current.get("KEEP_IMAGE", (None, ""))[1]:
            updates["KEEP_IMAGE"] = requested_image
        for name, requested in (("KEEP_TRANSPORT_MODE", transport_mode),
                                ("KEEP_BIND_ADDRESS", bind_address), ("KEEP_PORT", port)):
            existing = current.get(name, (None, ""))[1]
            if requested is not None:
                if existing and existing != str(requested):
                    raise InstallError(f"existing {name} conflicts with the requested setting; edit it explicitly first")
                if not existing:
                    updates[name] = str(requested)

        for key, value in updates.items():
            entry = current.get(key)
            line = f"{key}={value}\n"
            if entry:
                index = entry[0]
                ending = "\r\n" if lines[index].endswith("\r\n") else "\n"
                lines[index] = f"{key}={value}{ending}"
            else:
                if lines and not lines[-1].endswith(("\n", "\r")):
                    lines[-1] += "\n"
                lines.append(line)

        # KEEP_IMAGE is optional: Compose defaults to the current versioned image.
        content = "".join(lines).encode("utf-8")
        fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
        temporary = Path(temporary_name)
        try:
            _protect_created_file(fd, temporary)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            if os.name == "nt":
                _windows_private_acl(path)
            else:
                os.chmod(path, 0o600, follow_symlinks=False)
                dir_fd = os.open(parent, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    finally:
        os.close(lock_fd)


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        raise InstallError("installation download redirected; refusing an unexpected download location")


def download_release_file(name):
    if name not in ("VERSION", "compose.yml"):
        raise InstallError("unexpected installation file")
    request = Request(RELEASE_BASE + name, headers={"User-Agent": "Keep-Installer/" + RELEASE_VERSION})
    try:
        with build_opener(NoRedirects).open(request, timeout=30) as response:
            data = response.read(1024 * 1024 + 1)
    except InstallError:
        raise
    except OSError as error:
        raise InstallError("could not download the versioned installation files; check access and connectivity") from error
    if len(data) > 1024 * 1024:
        raise InstallError("installation file exceeded its size limit")
    return data


def _private_directory(directory):
    expanded = os.path.expanduser(str(directory))
    if os.name != "nt":
        # Check the written traversal before abspath removes '..' components.
        _posix_trusted_ancestors(Path(expanded).absolute().parent)
    path = Path(os.path.abspath(expanded))
    if os.name != "nt":
        _posix_trusted_ancestors(path.parent)
    created = False
    try:
        path.mkdir(mode=0o700)
        created = True
    except FileExistsError:
        pass
    if os.name == "nt" and created:
        _windows_private_acl(path, protect=True)
    _private_parent(path)
    return path


def _read_regular(path):
    _check_regular(path, missing_ok=False)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise InstallError(f"refusing non-regular file: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(1024 * 1024 + 1)
    finally:
        os.close(fd)
    if len(data) > 1024 * 1024:
        raise InstallError(f"local installation file exceeded its size limit: {path.name}")
    return data


def _write_new(path, data):
    # Link a complete, fsynced temporary file into place without ever replacing an
    # existing file. A failed download or interrupted write cannot become runnable.
    fd, temporary_name = tempfile.mkstemp(prefix=".keep-download-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        _protect_created_file(fd, temporary)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise InstallError(f"installation file appeared during setup; refusing to overwrite {path.name}") from error
    finally:
        temporary.unlink(missing_ok=True)


def prepare_bundle(directory, source_directory=None, downloader=download_release_file):
    paths = {name: directory / name for name in ("VERSION", "compose.yml")}
    existing = {name: _check_regular(path, missing_ok=True) is not None for name, path in paths.items()}
    if all(existing.values()):
        version = _read_regular(paths["VERSION"]).decode("ascii").strip()
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
            raise InstallError("existing VERSION is invalid; installation files were retained")
        _read_regular(paths["compose.yml"])
        return version
    data = {}
    for name in paths:
        data[name] = (_read_regular(Path(source_directory) / name) if source_directory is not None
                      else downloader(name))
        if not isinstance(data[name], bytes):
            raise InstallError("installation download did not return bytes")
    try:
        version = data["VERSION"].decode("ascii").strip()
        data["compose.yml"].decode("utf-8")
    except UnicodeError as error:
        raise InstallError("installation bundle is not valid text") from error
    if version != RELEASE_VERSION:
        raise InstallError(f"installation bundle must match release {RELEASE_VERSION}")
    if not data["compose.yml"].strip():
        raise InstallError("installation bundle has an empty Compose file")
    # Recover a partial earlier write only when the already-present file matches.
    for name, path in paths.items():
        if existing[name] and _read_regular(path) != data[name]:
            raise InstallError(f"existing {name} conflicts with the installation bundle; it was retained")
    for name, path in paths.items():
        if not existing[name]:
            _write_new(path, data[name])
    return version


def detect_lan_address():
    # UDP connect selects the route's local address without sending a packet.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.connect(("192.0.2.1", 9))
            address = validate_bind_address(connection.getsockname()[0])
            if ipaddress.ip_address(address).is_loopback:
                raise InstallError("no private LAN address was found; pass --bind-address explicitly")
            return address
    except OSError as error:
        raise InstallError("no private LAN address was found; pass --bind-address explicitly") from error


def check_port(address, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.bind((address, port))
    except OSError as error:
        raise InstallError("the selected address or port is unavailable; choose a local address and free --port") from error


def run_command(command, *, cwd, timeout):
    # Host shell variables must not override saved Compose settings or redirect the
    # operation to another project. Docker's sign-in and socket settings are kept.
    environment = {name: value for name, value in os.environ.items()
                   if not name.startswith(("KEEP_", "COMPOSE_")) and name != "FLASK_SECRET_KEY"}
    try:
        return subprocess.run(command, cwd=cwd, env=environment, check=False,
                              capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as error:
        raise InstallError("Docker is not installed or is not available in PATH") from error
    except subprocess.TimeoutExpired as error:
        raise InstallError("a Docker operation timed out; existing settings and data were retained") from error


def _run(runner, command, directory, message, timeout=60):
    result = runner(command, cwd=directory, timeout=timeout)
    if result.returncode:
        # Never echo Compose output which may include private environment values.
        raise InstallError(message)
    return result.stdout.strip()


def _compose_command(directory):
    return ["docker", "compose", "--project-name", "keep", "--project-directory", str(directory),
            "--env-file", str(directory / ".env"), "--file", str(directory / "compose.yml")]


def _containers_for_project(runner, directory):
    ids = _run(runner, ["docker", "ps", "--all", "--filter", "label=com.docker.compose.project=keep",
                        "--format", "{{.ID}}"], directory, "could not inspect existing Keep containers").split()
    if not ids:
        return []
    if not all(re.fullmatch(r"[a-f0-9]{12,64}", container_id) for container_id in ids):
        raise InstallError("Docker returned an invalid container ID")
    raw = _run(runner, ["docker", "inspect", *ids], directory, "could not inspect existing Keep containers")
    try:
        containers = json.loads(raw)
        for container in containers:
            labels = container["Config"]["Labels"]
            working_directory = labels.get("com.docker.compose.project.working_dir", "")
            if not working_directory or not os.path.isabs(working_directory) or os.path.realpath(working_directory) != os.path.realpath(directory):
                raise InstallError("a Keep Compose project already belongs to another directory; use its original installation directory")
    except (TypeError, KeyError, ValueError) as error:
        raise InstallError("Docker returned incomplete project information") from error
    return containers


def _saved_settings(directory):
    _, current = _read_env(directory / ".env")
    values = {name: item[1] for name, item in current.items()}
    mode = values.get("KEEP_TRANSPORT_MODE", "https")
    values["KEEP_URL"] = validate_url(values.get("KEEP_URL", ""), mode)
    values["KEEP_TRANSPORT_MODE"] = mode
    values["KEEP_BIND_ADDRESS"] = validate_bind_address(values.get("KEEP_BIND_ADDRESS", "127.0.0.1"))
    values["KEEP_PORT"] = validate_port(values.get("KEEP_PORT", "5000"))
    if values.get("KEEP_IMAGE"):
        validate_image(values["KEEP_IMAGE"])
    for name in ("FLASK_SECRET_KEY", "KEEP_WEBHOOK_SECRET"):
        if not SECRET_RE.fullmatch(values.get(name, "")):
            raise InstallError(f"existing {name} is invalid or missing; refusing to replace existing configuration")
    if mode == "lan-http":
        url = urlsplit(values["KEEP_URL"])
        if url.hostname != values["KEEP_BIND_ADDRESS"] or (url.port or 80) != values["KEEP_PORT"]:
            raise InstallError("saved LAN HTTP URL must match the saved bind address and port")
    return values


BOOTSTRAP_PROBE = """import json, os
from onboarding import Onboarding
store = Onboarding(os.environ.get('KEEP_DB_PATH', '/app/data/keep.sqlite3'), os.environ.get('PLEX_OWNER_ID', ''))
if store.owner():
    print(json.dumps({'owner_exists': True, 'pending': store.pending()}))
else:
    print(json.dumps({'owner_exists': False, 'code': store.issue()}))
"""


def start_installation(directory, *, requested_url=None, requested_image=None, bind_address=None,
                       port=None, source_directory=None, runner=run_command,
                       downloader=download_release_file, address_detector=detect_lan_address,
                       port_checker=check_port, sleep=time.sleep, monotonic=time.monotonic,
                       health_timeout=300, progress=print, skip_pull=False):
    directory = _private_directory(directory)
    # Keep the lock for the entire transaction, including the bootstrap issuance.
    lock_fd = _secure_lock(directory / ".keep-start")
    try:
        compose_version = _run(runner, ["docker", "compose", "version", "--short"], directory,
                               "Docker Compose v2 or newer is required")
        version_match = re.match(r"^v?([0-9]+)\.", compose_version)
        if not version_match or int(version_match.group(1)) < 2:
            raise InstallError("Docker Compose v2 or newer is required")
        _run(runner, ["docker", "info", "--format", "{{.ServerVersion}}"], directory,
             "Docker is not running or this user cannot access its daemon")
        docker_os = _run(runner, ["docker", "info", "--format", "{{.OSType}}"], directory,
                         "could not determine Docker's container mode")
        if docker_os != "linux":
            raise InstallError("Keep requires Linux containers; switch Docker Desktop to Linux containers")
        containers = _containers_for_project(runner, directory)
        env_exists = _check_regular(directory / ".env", missing_ok=True) is not None
        port_checked = False
        if env_exists:
            settings = _saved_settings(directory)
            for name, requested in (("KEEP_URL", requested_url), ("KEEP_IMAGE", requested_image),
                                    ("KEEP_BIND_ADDRESS", bind_address), ("KEEP_PORT", port)):
                if requested is not None:
                    if name == "KEEP_URL":
                        requested = validate_url(requested, settings["KEEP_TRANSPORT_MODE"])
                    elif name == "KEEP_BIND_ADDRESS":
                        requested = validate_bind_address(requested)
                    elif name == "KEEP_PORT":
                        requested = validate_port(requested)
                    elif name == "KEEP_IMAGE":
                        requested = validate_image(requested)
                    if str(settings.get(name, "")) != str(requested):
                        raise InstallError(f"existing {name} conflicts with the requested setting; it was retained")
            if not all(_check_regular(directory / name, missing_ok=True) is not None
                       for name in ("VERSION", "compose.yml")):
                raise InstallError("existing configuration requires its original VERSION and compose.yml; refusing an implicit upgrade")
            version = prepare_bundle(directory, source_directory, downloader)
            saved_image = settings.get("KEEP_IMAGE", "")
            if not containers and saved_image and not skip_pull and not (
                    re.search(r":[0-9]+\.[0-9]+\.[0-9]+$", saved_image) or "@sha256:" in saved_image):
                raise InstallError("restoring an existing installation requires a pinned version or digest image; refusing to pull a moving tag")
        else:
            if containers:
                raise InstallError("existing Keep containers have no matching .env; restore the original configuration first")
            labelled_volumes = _run(runner, ["docker", "volume", "ls", "--filter",
                                             "label=com.docker.compose.project=keep", "--format", "{{.Name}}"],
                                    directory, "could not inspect existing Keep data volumes").split()
            named_volumes = _run(runner, ["docker", "volume", "ls", "--filter", "name=keep_keep-data",
                                          "--format", "{{.Name}}"],
                                 directory, "could not inspect existing Keep data volumes").split()
            if labelled_volumes or "keep_keep-data" in named_volumes:
                raise InstallError("existing Keep data has no matching .env; restore the original installation files before starting")
            chosen_port = validate_port(5000 if port is None else port)
            if requested_url:
                url = validate_url(requested_url)
                mode = "https"
                address = validate_bind_address(bind_address or "127.0.0.1")
            else:
                address = validate_bind_address(bind_address or address_detector())
                mode = "lan-http"
                url = f"http://{address}:{chosen_port}"
            port_checker(address, chosen_port)
            port_checked = True
            version = prepare_bundle(directory, source_directory, downloader)
            install(directory / ".env", url, requested_image or "brspoon/keep:" + version,
                    transport_mode=mode, bind_address=address, port=chosen_port)
            settings = _saved_settings(directory)
        running_app = any(container.get("Config", {}).get("Labels", {}).get("com.docker.compose.service") == "keep-app"
                          and container.get("State", {}).get("Running") for container in containers)
        if not running_app and not port_checked:
            port_checker(settings["KEEP_BIND_ADDRESS"], settings["KEEP_PORT"])
        command = _compose_command(directory)
        _run(runner, command + ["config", "--quiet"], directory,
             "Compose configuration is invalid; inspect the installation files")
        if containers:
            progress("Keeping the existing service containers and image…")
        elif skip_pull:
            image = settings.get("KEEP_IMAGE") or "brspoon/keep:" + version
            _run(runner, ["docker", "image", "inspect", "--format", "{{.Id}}", image], directory,
                 "--skip-pull requires the configured image to be present locally")
        else:
            progress("Pulling Keep's versioned image…")
            _run(runner, command + ["pull", "keep-app", "keep-digest"], directory,
                 "could not pull Keep's image; check connectivity and Docker Hub access (private images require docker login)", timeout=600)
        progress("Starting Keep and its email worker…")
        start_options = ["--no-recreate", "--pull", "never"] if containers or skip_pull else []
        _run(runner, command + ["up", "--detach", *start_options, "keep-app", "keep-digest"], directory,
             "could not start Keep's services; existing configuration and data were retained", timeout=180)
        progress("Waiting for both services to become healthy…")
        deadline = monotonic() + health_timeout
        while True:
            ids = _run(runner, command + ["ps", "--all", "--quiet", "keep-app", "keep-digest"],
                       directory, "could not inspect Keep's service state").split()
            if ids and not all(re.fullmatch(r"[a-f0-9]{12,64}", identifier) for identifier in ids):
                raise InstallError("Docker returned an invalid service container ID")
            current = []
            if ids:
                raw = _run(runner, ["docker", "inspect", *ids], directory, "could not inspect Keep's health")
                try:
                    current = json.loads(raw)
                except (TypeError, ValueError) as error:
                    raise InstallError("Docker returned invalid health information") from error
            services = {container.get("Config", {}).get("Labels", {}).get("com.docker.compose.service"): container
                        for container in current}
            healthy = all(services.get(name, {}).get("State", {}).get("Running") and
                          services.get(name, {}).get("State", {}).get("Health", {}).get("Status") == "healthy"
                          for name in ("keep-app", "keep-digest"))
            if healthy:
                break
            if any(container.get("State", {}).get("Health", {}).get("Status") == "unhealthy"
                   or container.get("State", {}).get("Status") in ("dead", "exited") for container in current):
                raise InstallError("a Keep service failed its health check; inspect docker compose logs in the installation directory")
            if monotonic() >= deadline:
                raise InstallError("Keep's services did not become healthy in time; configuration and data were retained. Rerun the installer after resolving the service issue")
            sleep(2)
        raw = _run(runner, command + ["exec", "--no-TTY", "keep-app", "python", "-c", BOOTSTRAP_PROBE],
                   directory, "could not prepare owner setup; existing ownership and data were retained")
        try:
            bootstrap = json.loads(raw)
            if not isinstance(bootstrap.get("owner_exists"), bool):
                raise ValueError("missing owner state")
            if not bootstrap["owner_exists"] and not re.fullmatch(r"[A-Za-z0-9_-]{40,100}", bootstrap.get("code", "")):
                raise ValueError("invalid setup code")
        except (AttributeError, TypeError, ValueError) as error:
            raise InstallError("Keep returned an invalid owner setup response; no credentials were displayed") from error
        return {"directory": directory, "url": settings["KEEP_URL"], "version": version, **bootstrap}
    finally:
        os.close(lock_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    if sys.version_info < (3, 9):
        parser.exit(2, "Keep requires Python 3.9 or newer.\n")
    parser.add_argument("--start", action="store_true", help="install files, start both services, and print owner setup instructions")
    parser.add_argument("--directory", type=Path, default=Path.home() / "keep", help="installation directory (default: ~/keep)")
    parser.add_argument("--bind-address", help="local private IPv4 address (auto-detected for a new LAN installation)")
    parser.add_argument("--port", type=int, help="local HTTP port (default: 5000)")
    parser.add_argument("--url", help="optional HTTPS origin; omit with --start for local HTTP")
    parser.add_argument("--image", help="optional explicit image tag or sha256 digest")
    parser.add_argument("--env", type=Path, default=Path(".env"), help="configuration-only env file (default: .env)")
    parser.add_argument("--source-directory", type=Path, help="use VERSION and compose.yml from an authorized local release checkout")
    parser.add_argument("--skip-pull", action="store_true", help="use an already-present image for an offline installation or local candidate trial")
    args = parser.parse_args(argv)
    if not args.start and not args.url:
        parser.error("--url is required unless --start is used")
    if not args.start and (args.bind_address or args.port is not None or args.source_directory or args.skip_pull):
        parser.error("--bind-address, --port, --source-directory, and --skip-pull require --start")
    if args.start and args.env != Path(".env"):
        parser.error("--start uses .env inside --directory; --env is configuration-only")
    try:
        if args.start:
            result = start_installation(args.directory, requested_url=args.url, requested_image=args.image,
                                        bind_address=args.bind_address, port=args.port,
                                        source_directory=args.source_directory, skip_pull=args.skip_pull)
            print(f"Keep is healthy. Installation directory: {result['directory']}")
            if result["owner_exists"]:
                print(f"Open {result['url']}{'/setup' if result.get('pending') else ''}")
                print("The existing owner and installation settings were preserved.")
            else:
                print(f"Open {result['url']}/setup")
                print(f"Owner setup code (valid for 10 minutes): {result['code']}")
                print("Complete Plex sign-in and choose your Maintainerr collections in the browser.")
                print("If the code expires, rerun this installer to issue another.")
        else:
            install(args.env, args.url, args.image)
            print(f"Keep configuration is ready at {args.env}; secrets were not displayed.")
    except (InstallError, OSError, UnicodeError) as error:
        parser.exit(2, f"Keep installation failed: {error}\n")


if __name__ == "__main__":
    main()
