param(
    [Parameter(Mandatory = $true)][string]$Workspace,
    [Parameter(Mandatory = $true)][string]$HostProfile,
    [Parameter(Mandatory = $true)][string]$PrivateFile,
    [Parameter(Mandatory = $true)][string]$CredentialsFile
)

$ErrorActionPreference = 'Stop'

function Can-ReadFile([string]$Path) {
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        $stream.Dispose()
        return $true
    } catch {
        return $false
    }
}

function Can-ListDirectory([string]$Path) {
    try {
        [void][System.IO.Directory]::GetFileSystemEntries($Path)
        return $true
    } catch {
        return $false
    }
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$output = Join-Path $Workspace 'sandbox-probe-result.json'
$created = Join-Path $Workspace 'written-by-sandbox.txt'

try {
    [System.IO.File]::WriteAllText($created, 'sandbox workspace write succeeded')
    $canWriteWorkspace = $true
} catch {
    $canWriteWorkspace = $false
}

$result = [ordered]@{
    identity = $identity.Name
    sid = $identity.User.Value
    canReadWorkspace = Can-ReadFile (Join-Path $Workspace 'before-add.txt')
    canWriteWorkspace = $canWriteWorkspace
    canListProfile = Can-ListDirectory $HostProfile
    canReadHostSibling = Can-ReadFile $PrivateFile
    canReadCredentials = Can-ReadFile $CredentialsFile
}

[System.IO.File]::WriteAllText($output, ($result | ConvertTo-Json))
