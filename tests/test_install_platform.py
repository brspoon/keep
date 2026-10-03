"""Native Windows permission/locking checks; shared orchestration uses fake Docker."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import install_keep


@unittest.skipUnless(os.name == "nt", "requires native Windows ACLs and locks")
class WindowsInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.parent = Path(self.temp.name)
        self.directory = install_keep._private_directory(self.parent / "keep")

    def tearDown(self):
        self.temp.cleanup()

    def test_private_configuration_is_created_and_preserved_without_unix_calls(self):
        env = self.directory / ".env"
        install_keep.install(env, "http://127.0.0.1:5000", "brspoon/keep:2.21.2",
                             transport_mode="lan-http", bind_address="127.0.0.1", port=5000)
        before = env.read_bytes()
        install_keep._windows_private_acl(env)
        install_keep.install(env, "http://127.0.0.1:5000", "brspoon/keep:2.21.2",
                             transport_mode="lan-http", bind_address="127.0.0.1", port=5000)
        self.assertEqual(env.read_bytes(), before)
        self.assertIn(b"KEEP_TRANSPORT_MODE=lan-http", before)

    def test_acl_grant_to_another_identity_is_refused_without_changing_the_file(self):
        env = self.directory / ".env"
        install_keep.install(env, "https://keep.example.org")
        before = env.read_bytes()
        script = r"""
$path = $env:KEEP_TEST_ACL_PATH
$acl = Get-Acl -LiteralPath $path
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
    [System.Security.AccessControl.FileSystemRights]::Read,
    [System.Security.AccessControl.AccessControlType]::Allow)
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $path -AclObject $acl
"""
        changed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                                 env={**os.environ, "KEEP_TEST_ACL_PATH": str(env)}, capture_output=True)
        self.assertEqual(changed.returncode, 0)
        with self.assertRaisesRegex(install_keep.InstallError, "private"):
            install_keep.install(env, "https://keep.example.org")
        self.assertEqual(env.read_bytes(), before)

    def test_junction_installation_path_is_refused(self):
        alias = self.parent / "junction"
        created = subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(alias), str(self.directory)],
                                 capture_output=True)
        self.assertEqual(created.returncode, 0)
        try:
            with self.assertRaises(install_keep.InstallError):
                install_keep._private_directory(alias)
        finally:
            alias.rmdir()

    def test_native_lock_excludes_another_installer_process(self):
        lock_target = self.directory / "sample"
        descriptor = install_keep._secure_lock(lock_target)
        script = """import os, sys
sys.path.insert(0, sys.argv[1])
import install_keep
try:
    fd = install_keep._secure_lock(__import__('pathlib').Path(sys.argv[2]))
except OSError:
    sys.exit(0)
else:
    os.close(fd)
    sys.exit(1)
"""
        try:
            child = subprocess.run([sys.executable, "-c", script,
                                    str(Path(install_keep.__file__).parent), str(lock_target)],
                                   capture_output=True, timeout=30)
            self.assertEqual(child.returncode, 0)
        finally:
            os.close(descriptor)

    def test_powershell_launcher_forwards_arguments_and_cleans_failed_download(self):
        launcher = Path(__file__).resolve().parents[1] / "install.ps1"
        # Mock the download inside PowerShell, while running the genuine downloaded
        # Python payload. This exercises native quoting, ACLs, cleanup and failure.
        script = r"""
$ErrorActionPreference = 'Stop'
function Invoke-WebRequest {
    param($Uri, [switch]$UseBasicParsing, $MaximumRedirection, $TimeoutSec, $OutFile, [switch]$PassThru, $ErrorAction)
    if ($env:KEEP_TEST_DOWNLOAD_FAIL -eq 'yes') {
        Set-Content -LiteralPath $OutFile -Value 'partial download'
        throw 'simulated download failure'
    }
    $payload = @'
import json, os, sys
from pathlib import Path
Path(os.environ['KEEP_TEST_ARGUMENTS']).write_text(json.dumps(sys.argv[1:]))
Path(os.environ['KEEP_TEST_TEMP']).write_text(str(Path(__file__).parent))
'@
    Set-Content -LiteralPath $OutFile -Value $payload -Encoding UTF8
    [pscustomobject]@{ StatusCode = 200 }
}
if ($env:KEEP_TEST_LAUNCHER_MODE -eq 'iex') {
    Get-Content -LiteralPath $env:KEEP_TEST_LAUNCHER -Raw | Invoke-Expression
} else {
    & $env:KEEP_TEST_LAUNCHER --directory 'C:\Keep Folder' --port 8788
}
"""
        arguments = self.parent / "arguments.json"
        temporary = self.parent / "temporary.txt"
        environment = {**os.environ, "KEEP_TEST_LAUNCHER": str(launcher),
                       "KEEP_TEST_ARGUMENTS": str(arguments), "KEEP_TEST_TEMP": str(temporary)}
        completed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                                   env=environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(arguments.read_text()),
                         ["--start", "--directory", r"C:\Keep Folder", "--port", "8788"])
        self.assertFalse(Path(temporary.read_text()).exists())
        arguments.unlink()
        inline = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                                env={**environment, "KEEP_TEST_LAUNCHER_MODE": "iex"},
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(inline.returncode, 0, inline.stderr)
        self.assertEqual(json.loads(arguments.read_text()), ["--start"])
        self.assertFalse(Path(temporary.read_text()).exists())
        arguments.unlink()
        failed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                                env={**environment, "KEEP_TEST_DOWNLOAD_FAIL": "yes"},
                                capture_output=True, text=True, timeout=60)
        self.assertNotEqual(failed.returncode, 0)
        self.assertFalse(arguments.exists())

    def test_powershell_python_guidance_never_installs_or_downloads_prerequisites(self):
        launcher = Path(__file__).resolve().parents[1] / 'install.ps1'
        record = self.parent / 'prerequisite-execution.txt'
        script = r"""
$ErrorActionPreference = 'Stop'
function Get-Command {
    param([string]$Name, $ErrorAction)
    if ($Name -eq 'winget' -and $env:KEEP_TEST_WINGET -eq 'yes') {
        return [pscustomobject]@{ Source = 'winget' }
    }
    if ($Name -eq 'py' -and $env:KEEP_TEST_PYTHON -eq 'old') {
        return [pscustomobject]@{ Source = 'Invoke-KeepOldPython' }
    }
    return $null
}
function Invoke-KeepOldPython {
    Add-Content -LiteralPath $env:KEEP_TEST_EVENTS -Value 'python-version' -Encoding ASCII
    $global:LASTEXITCODE = 1
}
function Invoke-WebRequest {
    Add-Content -LiteralPath $env:KEEP_TEST_EVENTS -Value 'download' -Encoding ASCII
    throw 'Download must not run while Python is unavailable'
}
function New-Item {
    Add-Content -LiteralPath $env:KEEP_TEST_EVENTS -Value 'temporary-directory' -Encoding ASCII
    throw 'Temporary directory must not be created while Python is unavailable'
}
function winget {
    Add-Content -LiteralPath $env:KEEP_TEST_EVENTS -Value 'winget' -Encoding ASCII
    throw 'Prerequisites must not be installed automatically'
}
try {
    & $env:KEEP_TEST_LAUNCHER
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
exit 0
"""
        for python in ('missing', 'old'):
            for winget in ('yes', 'no'):
                with self.subTest(python=python, winget=winget):
                    record.unlink(missing_ok=True)
                    result = subprocess.run(
                        ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                        env={**os.environ, 'KEEP_TEST_LAUNCHER': str(launcher),
                             'KEEP_TEST_EVENTS': str(record), 'KEEP_TEST_PYTHON': python,
                             'KEEP_TEST_WINGET': winget},
                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn('Keep requires Python 3.9 or newer.', result.stderr)
                    self.assertIn('Reopen PowerShell', result.stderr)
                    if winget == 'yes':
                        self.assertIn('winget install --id Python.Python.3.14 --exact', result.stderr)
                    else:
                        self.assertIn('https://www.python.org/downloads/windows/', result.stderr)
                        self.assertNotIn('winget install', result.stderr)
                    self.assertEqual(record.read_text().splitlines() if record.exists() else [],
                                     ['python-version'] if python == 'old' else [])


if __name__ == "__main__":
    unittest.main()
