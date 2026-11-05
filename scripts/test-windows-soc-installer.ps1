# Lifecycle test for a disposable machine or CI runner. Everyone cases need an elevated shell.
param([string]$Setup, [string]$NextSetup, [switch]$JustMeOnly)
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$identity = Get-Content -Raw -LiteralPath 'windows-soc-version.json' | ConvertFrom-Json
if (-not $Setup) { $Setup = Join-Path $PWD "dist/AtlasSOC-Setup-$($identity.version)-build$($identity.build).exe" }
$Setup = (Resolve-Path -LiteralPath $Setup).Path
$appId = ([regex]'AppGuid "([0-9A-Fa-f-]+)"').Match((Get-Content -Raw -LiteralPath 'installer/AtlasSOC.iss')).Groups[1].Value
$key = "Software\Microsoft\Windows\CurrentVersion\Uninstall\{$appId}_is1"
$scopes = @{
    JustMe = @{ Flag = '/CURRENTUSER'; Dir = Join-Path $env:LOCALAPPDATA 'Programs\AtlasSOC'; Hive = "HKCU:\$key"
        Desktop = [Environment]::GetFolderPath('Desktop'); Menu = [Environment]::GetFolderPath('Programs') }
    Everyone = @{ Flag = '/ALLUSERS'; Dir = Join-Path $env:ProgramFiles 'AtlasSOC'; Hive = "HKLM:\$key"
        Desktop = [Environment]::GetFolderPath('CommonDesktopDirectory'); Menu = [Environment]::GetFolderPath('CommonPrograms') }
}
$order = if ($JustMeOnly) { @('JustMe') } else { @('JustMe', 'Everyone') }
function Run-Setup([string[]] $Arguments) {
    (Start-Process -FilePath $Setup -ArgumentList (@('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') + $Arguments) -Wait -PassThru).ExitCode
}
function Uninstall-Scope($Scope) {
    $command = (Get-ItemProperty -LiteralPath $Scope.Hive).QuietUninstallString
    $exe = ($command -split '"')[1]
    $code = (Start-Process -FilePath $exe -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -Wait -PassThru).ExitCode
    if ($code) { throw "Uninstall failed: $code" }
    for ($i = 0; $i -lt 40 -and (Test-Path -LiteralPath (Join-Path $Scope.Dir 'unins000.exe')); $i++) { Start-Sleep -Milliseconds 250 }
}
function Assert-Shortcut([string] $Path, [bool] $Expected) {
    if ((Test-Path -LiteralPath $Path) -ne $Expected) { throw "Shortcut expected=$Expected at $Path" }
}
$desktopPrefs = 'SCRNSAVE.EXE', 'ScreenSaveTimeOut', 'ScreenSaverIsSecure', 'ScreenSaveActive'
$before = Get-ItemProperty 'HKCU:\Control Panel\Desktop'
$data = Join-Path $env:LOCALAPPDATA 'ThreatAtlasSOC'
$marker = Join-Path $data 'installer-test-marker.txt'
$dataExisted = Test-Path -LiteralPath $data
New-Item -ItemType Directory -Force -Path $data | Out-Null
Set-Content -LiteralPath $marker -Value 'keep'
try {
    foreach ($name in $order) {
        $scope = $scopes[$name]
        foreach ($case in @(@{D=$false;S=$false}, @{D=$true;S=$false}, @{D=$false;S=$true}, @{D=$true;S=$true})) {
            $tasks = (@(if ($case.D) { 'desktopicon' }; if ($case.S) { 'startmenu' }) -join ',')
            $code = Run-Setup @($scope.Flag, "/TASKS=`"$tasks`"")
            if ($code) { throw "$name install failed: $code" }
            $exe = Join-Path $scope.Dir 'AtlasSOC.exe'
            if (-not (Test-Path -LiteralPath $exe)) { throw "$name missing $exe" }
            if (-not (Test-Path -LiteralPath $scope.Hive)) { throw "$name not registered in its own Installed apps context" }
            if ((Get-ItemProperty -LiteralPath $scope.Hive).Publisher -ne 'Ibert Consulting') { throw 'Wrong publisher' }
            Assert-Shortcut (Join-Path $scope.Desktop 'AtlasSOC.lnk') $case.D
            Assert-Shortcut (Join-Path $scope.Menu 'AtlasSOC.lnk') $case.S
            if (Get-ChildItem -LiteralPath $scope.Dir -Recurse -File | Where-Object Name -match '\.(log|cache)$|^(settings|consent)\.json$') { throw 'Runtime data in the install folder' }
            Uninstall-Scope $scope
            if (Test-Path -LiteralPath $exe) { throw "$name uninstall left the EXE" }
            if (Test-Path -LiteralPath $scope.Hive) { throw "$name uninstall left the registration" }
            Assert-Shortcut (Join-Path $scope.Desktop 'AtlasSOC.lnk') $false
            Assert-Shortcut (Join-Path $scope.Menu 'AtlasSOC.lnk') $false
            if (-not (Test-Path -LiteralPath $marker)) { throw 'Uninstall removed user data' }
            Write-Output "PASS $name desktop=$($case.D) startmenu=$($case.S)"
        }
        # Same-version repair keeps a chosen absence of shortcuts.
        if (Run-Setup @($scope.Flag, '/TASKS="startmenu"')) { throw 'Repair base install failed' }
        Remove-Item -LiteralPath (Join-Path $scope.Dir 'AtlasSOC.exe')
        if (Run-Setup @($scope.Flag)) { throw 'Repair failed' }
        if (-not (Test-Path -LiteralPath (Join-Path $scope.Dir 'AtlasSOC.exe'))) { throw 'Repair did not restore the EXE' }
        Assert-Shortcut (Join-Path $scope.Desktop 'AtlasSOC.lnk') $false
        Write-Output "PASS $name repair"
        Uninstall-Scope $scope
    }
    if (-not $JustMeOnly) {
        if (Run-Setup @('/CURRENTUSER', '/TASKS="startmenu"')) { throw 'Conflict base install failed' }
        if ((Run-Setup @('/ALLUSERS', '/TASKS="startmenu"')) -eq 0) { throw 'Other-scope install was not refused' }
        if (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'AtlasSOC\AtlasSOC.exe')) { throw 'Refused install wrote files' }
        Uninstall-Scope $scopes.JustMe
        Write-Output 'PASS scope conflict refused'
    }
    if ($NextSetup) {
        $NextSetup = (Resolve-Path -LiteralPath $NextSetup).Path
        foreach ($name in $order) {
            $scope = $scopes[$name]
            if (Run-Setup @($scope.Flag, '/TASKS="startmenu"')) { throw 'Upgrade base install failed' }
            $code = (Start-Process -FilePath $NextSetup -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', $scope.Flag -Wait -PassThru).ExitCode
            if ($code) { throw "$name upgrade failed: $code" }
            $entry = Get-ItemProperty -LiteralPath $scope.Hive
            if ($entry.DisplayVersion -eq $identity.version) { throw 'Upgrade kept the old version' }
            Assert-Shortcut (Join-Path $scope.Menu 'AtlasSOC.lnk') $true
            Assert-Shortcut (Join-Path $scope.Desktop 'AtlasSOC.lnk') $false
            if (-not (Test-Path -LiteralPath $marker)) { throw 'Upgrade removed user data' }
            Write-Output "PASS $name upgrade keeps shortcut choices and user data"
            Uninstall-Scope $scope
        }
    }
    $after = Get-ItemProperty 'HKCU:\Control Panel\Desktop'
    foreach ($property in $desktopPrefs) { if ($before.$property -ne $after.$property) { throw "Installer changed $property" } }
    Write-Output 'PASS installer lifecycle, user data and screensaver settings preserved.'
} finally {
    Remove-Item -LiteralPath $marker -ErrorAction SilentlyContinue
    if (-not $dataExisted) { Remove-Item -LiteralPath $data -Recurse -ErrorAction SilentlyContinue }
}
