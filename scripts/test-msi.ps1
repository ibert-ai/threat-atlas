# Run only on a disposable Windows test machine/CI runner, elevated: installs per-machine.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$release = Get-Content (Join-Path $PWD 'version.json') -Raw | ConvertFrom-Json
$msi = (Resolve-Path (Join-Path 'dist' ('ThreatAtlas-' + $release.version + '-x64.msi'))).Path
$saver = Join-Path ([Environment]::SystemDirectory) 'ThreatAtlas.scr'
$wow64 = Join-Path $env:WINDIR 'SysWOW64\ThreatAtlas.scr'
$docs = Join-Path $env:ProgramFiles 'Threat Atlas'
$menu = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Threat Atlas SOC'
$userKey = 'HKCU:\Software\Ibert Consulting\ThreatAtlas'
if ((Test-Path $saver) -or (Test-Path $docs)) { throw 'Test requires a clean machine without Threat Atlas installed.' }
$before = Get-ItemProperty 'HKCU:\Control Panel\Desktop'
function Start-Msi([string] $operation) {
    (Start-Process msiexec.exe -ArgumentList "$operation `"$msi`" /qn /norestart" -Wait -PassThru).ExitCode
}
function Invoke-Msi([string] $operation) {
    $code = Start-Msi $operation
    if ($code -notin 0,3010) { throw "MSI failed: $code" }
}
# An older per-user install must block rather than leave a second copy behind.
New-Item $userKey -Force | Out-Null
New-ItemProperty $userKey -Name InstallPath -Value 'C:\fixture\' -Force | Out-Null
try {
    if ((Start-Msi '/i') -ne 1603) { throw 'Installer did not refuse an existing per-user install' }
    if (Test-Path $saver) { throw 'Refused install still wrote the SCR' }
} finally { Remove-Item $userKey -Recurse -Force }
try {
    Invoke-Msi '/i'
    if (!(Test-Path $saver)) { throw 'Missing SCR in System32' }
    if (Test-Path $wow64) { throw 'SCR must not be copied to SysWOW64' }
    if (Test-Path (Join-Path $env:LOCALAPPDATA 'ThreatAtlas\ThreatAtlas.scr')) { throw 'SCR installed per-user' }
    if (!(Test-Path (Join-Path $docs 'INSTALL.txt'))) { throw 'Missing installation guide' }
    foreach ($name in 'Set up Threat Atlas','Preview Threat Atlas','Installation instructions') {
        if (!(Test-Path (Join-Path $menu "$name.lnk"))) { throw "Missing shortcut: $name" }
    }
    $after = Get-ItemProperty 'HKCU:\Control Panel\Desktop'
    foreach ($property in 'SCRNSAVE.EXE','ScreenSaveTimeOut','ScreenSaverIsSecure','ScreenSaveActive') {
        if ($before.$property -ne $after.$property) { throw "Installer changed $property" }
    }
} finally {
    Invoke-Msi '/x'
}
if (Test-Path $saver) { throw 'Uninstall left SCR behind' }
if (Test-Path $docs) { throw 'Uninstall left documentation behind' }
if (Test-Path $menu) { throw 'Uninstall left Start Menu folder behind' }
Write-Host 'MSI per-machine install, per-user refusal, shortcuts, preferences preservation and uninstall passed.'
