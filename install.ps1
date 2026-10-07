# Download the complete versioned installer, then run it with Python 3.9+.
# Requires Windows PowerShell 5.1+ and Docker Desktop using Linux containers.
$ErrorActionPreference = 'Stop'
$installerArguments = @($args)
if ($PSVersionTable.PSVersion -lt [Version]'5.1') {
    throw 'Keep requires PowerShell 5.1 or newer. Install a supported version: https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-windows'
}
function Get-KeepPythonHelp {
    $guidance = @('Install Python 3.9 or newer: https://www.python.org/downloads/windows/')
    if ($null -ne (Get-Command winget -ErrorAction SilentlyContinue)) {
        $guidance = @('Install with your existing WinGet:', 'winget install --id Python.Python.3.14 --exact')
    }
    $guidance += 'Reopen PowerShell, check py -3 --version or python --version, then rerun the Keep installation command.'
    return ($guidance -join [Environment]::NewLine)
}
$python = Get-Command py -ErrorAction SilentlyContinue
$pythonPrefix = @('-3')
if ($null -eq $python) {
    $python = Get-Command python -ErrorAction SilentlyContinue
    $pythonPrefix = @()
}
if ($null -eq $python) { throw ('Keep requires Python 3.9 or newer.' + [Environment]::NewLine + (Get-KeepPythonHelp)) }
& $python.Source @pythonPrefix -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'
if ($LASTEXITCODE -ne 0) { throw ('Keep requires Python 3.9 or newer.' + [Environment]::NewLine + (Get-KeepPythonHelp)) }

$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ('keep-install-' + [guid]::NewGuid().ToString('N'))
$installerPath = Join-Path $temporary 'install_keep.py'
$previousProtocol = [System.Net.ServicePointManager]::SecurityProtocol
try {
    # Windows PowerShell 5.1 uses .NET's ServicePointManager for HTTPS requests.
    [System.Net.ServicePointManager]::SecurityProtocol = $previousProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    $item = New-Item -ItemType Directory -Path $temporary
    $ancestor = $item
    while ($null -ne $ancestor) {
        if (($ancestor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Keep installation paths cannot contain junctions or reparse points.'
        }
        $ancestor = $ancestor.Parent
    }
    $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetOwner($current)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sidText in @($current.Value, 'S-1-5-18', 'S-1-5-32-544')) {
        $sid = [System.Security.Principal.SecurityIdentifier]::new($sidText)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $temporary -AclObject $acl
    # MaximumRedirection=0 rejects redirects. Python runs only after a successful,
    # complete HTTPS download; a failed transfer is removed in the finally block.
    $download = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/brspoon/keep/2.23.3/scripts/install_keep.py' `
        -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 120 -OutFile $installerPath -PassThru -ErrorAction Stop
    if ($download.StatusCode -ne 200) { throw 'Keep installer download returned an unexpected status.' }
    & $python.Source @pythonPrefix $installerPath --start @installerArguments
    if ($LASTEXITCODE -ne 0) { throw 'Keep installation did not complete. Resolve the reported issue, then rerun the command.' }
} finally {
    [System.Net.ServicePointManager]::SecurityProtocol = $previousProtocol
    if (Test-Path -LiteralPath $installerPath) { Remove-Item -LiteralPath $installerPath -Force }
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
}
