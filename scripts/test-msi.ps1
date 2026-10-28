# Run only on a disposable Windows test account/CI runner.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$msi = (Resolve-Path 'dist/ThreatAtlas-0.3.0-x64.msi').Path
$installDir = Join-Path $env:LOCALAPPDATA 'ThreatAtlas'
if (Test-Path $installDir) { throw 'Test requires a clean account without Threat Atlas installed.' }
$before = Get-ItemProperty 'HKCU:\Control Panel\Desktop'
$beforeSelection = $before.'SCRNSAVE.EXE'
function Invoke-Msi([string] $operation) {
    $process = Start-Process msiexec.exe -ArgumentList "$operation `"$msi`" /qn /norestart" -Wait -PassThru
    if ($process.ExitCode -notin 0,3010) { throw "MSI failed: $($process.ExitCode)" }
}
try {
    Invoke-Msi '/i'
    if (!(Test-Path (Join-Path $installDir 'ThreatAtlas.scr'))) { throw 'Missing SCR' }
    $menu = Join-Path ([Environment]::GetFolderPath('Programs')) 'Threat Atlas SOC'
    foreach ($name in 'Set up Threat Atlas','Preview Threat Atlas','Installation instructions','Enable automatic updates','Disable automatic updates','Check for updates') {
        if (!(Test-Path (Join-Path $menu "$name.lnk"))) { throw "Missing shortcut: $name" }
    }
    # Unsigned CI builds must fail before registering a task or fetching updates.
    if ((Get-AuthenticodeSignature (Join-Path $installDir 'ThreatAtlas.scr')).Status -eq 'NotSigned') {
        $updater = Join-Path $installDir 'Update-ThreatAtlas.ps1'
        $check = Start-Process powershell.exe -ArgumentList "-NoProfile -NonInteractive -File `"$updater`" -Mode Enable" -Wait -PassThru
        if ($check.ExitCode -eq 0) { throw 'Unsigned build enabled automatic updates' }
        $status = Get-Content (Join-Path $installDir 'update-status.txt') -Raw
        if ($status -notmatch 'trusted code signature') { throw "Unexpected unsigned-build failure: $status" }
        Remove-Item (Join-Path $installDir 'update-status.txt')
    }
    & (Join-Path $installDir 'Update-ThreatAtlas.ps1') -Mode Disable
    $after = Get-ItemProperty 'HKCU:\Control Panel\Desktop'
    foreach ($property in 'SCRNSAVE.EXE','ScreenSaveTimeOut','ScreenSaverIsSecure','ScreenSaveActive') {
        if ($before.$property -ne $after.$property) { throw "Installer changed $property" }
    }
} finally {
    Invoke-Msi '/x'
}
if (Test-Path (Join-Path $installDir 'ThreatAtlas.scr')) { throw 'Uninstall left SCR behind' }
if (Test-Path $menu) { throw 'Uninstall left Start Menu folder behind' }
Write-Host 'MSI install, shortcuts, preferences preservation and uninstall passed.'
