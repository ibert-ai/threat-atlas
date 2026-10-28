param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$Thumbprint,
    [Parameter(Mandatory=$true)][string]$File,
    [string]$TimestampUrl = 'https://timestamp.digicert.com'
)
$ErrorActionPreference = 'Stop'
# Use a Windows certificate-store identity backed by your token/cloud provider.
# No private key or password is stored in the repository.
$tool = Get-Command signtool.exe -ErrorAction SilentlyContinue
if ($tool) { $signTool = $tool.Source } else {
    $signTool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" |
        Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (!$signTool) { throw 'Install the Windows SDK signing tools.' }
$path = (Resolve-Path $File).Path
& $signTool sign /sha1 $Thumbprint /s My /fd SHA256 /tr $TimestampUrl /td SHA256 $path
if ($LASTEXITCODE -ne 0) { throw 'Signing failed' }
& $signTool verify /pa /all /v $path
if ($LASTEXITCODE -ne 0) { throw 'Signature verification failed' }
