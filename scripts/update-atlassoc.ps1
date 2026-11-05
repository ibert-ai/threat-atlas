<#
.SYNOPSIS
    Downloads the newest AtlasSOC Desktop installer for Windows and starts it.

.DESCRIPTION
    Reads the public ibert-ai/threat-atlas GitHub releases, picks the newest
    AtlasSOC release for the chosen channel, checks the installer's SHA256
    against the digest GitHub reports, and starts the normal installer window.
    The installer stays interactive: you choose the install scope, approve any
    Windows prompt, and accept the licence in the app yourself.

    Channels:
      stable  Only full AtlasSOC releases.
      beta    The newest AtlasSOC release, including pre-releases.

.PARAMETER Channel
    stable or beta. If left out, the script asks.

.PARAMETER Force
    Runs the installer even when that version is already installed.

.PARAMETER DownloadOnly
    Downloads and verifies the installer, but does not start it.

.PARAMETER Silent
    Upgrades without the installer wizard, in the existing install scope, and
    opens AtlasSOC afterwards. Windows prompts still appear. The app uses this.

.PARAMETER WaitPid
    Waits for this process to end before installing. The app passes its own ID.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\update-atlassoc.ps1 -Channel beta
#>
[CmdletBinding()]
param(
    [ValidateSet('stable', 'beta')]
    [string]$Channel,
    [switch]$Force,
    [switch]$DownloadOnly,
    [switch]$Silent,
    [int]$WaitPid = 0
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ReleasesApi = 'https://api.github.com/repos/ibert-ai/threat-atlas/releases?per_page=100'
$TagPattern = '^atlassoc-v\d+\.\d+\.\d+'
$AssetPattern = '^AtlasSOC-Setup-(\d+\.\d+\.\d+)-build(\d+)\.exe$'
$Headers = @{
    'User-Agent' = 'AtlasSOC-Updater'
    'Accept'     = 'application/vnd.github+json'
}

$ProgramFilesExe = Join-Path $env:ProgramFiles 'AtlasSOC\AtlasSOC.exe'
$PerUserExe = Join-Path $env:LOCALAPPDATA 'Programs\AtlasSOC\AtlasSOC.exe'

function Start-AtlasSOC {
    foreach ($path in @($ProgramFilesExe, $PerUserExe)) {
        if (Test-Path -LiteralPath $path) {
            Start-Process -FilePath $path
            return
        }
    }
}

trap {
    Write-Host "Update failed: $_"
    if ($Silent) {
        Start-AtlasSOC
        Read-Host 'Press Enter to close'
    }
    exit 1
}

function Select-Channel {
    Write-Host ''
    Write-Host 'Which AtlasSOC version do you want?'
    Write-Host '  1. Stable (full releases only)'
    Write-Host '  2. Beta (newest version, including pre-releases)'
    while ($true) {
        switch ((Read-Host 'Choose 1 or 2').Trim()) {
            '1' { return 'stable' }
            '2' { return 'beta' }
            default { Write-Host 'Please type 1 or 2.' }
        }
    }
}

function Get-InstallerAsset($Release) {
    foreach ($asset in $Release.assets) {
        if ($asset.name -match $AssetPattern) {
            return [pscustomobject]@{
                Name    = $asset.name
                Url     = $asset.browser_download_url
                Digest  = $asset.digest
                Version = [version]('{0}.{1}' -f $Matches[1], $Matches[2])
            }
        }
    }
    return $null
}

function Get-LatestInstaller([string]$SelectedChannel) {
    # Windows PowerShell 5.1 returns the JSON array as one object; the pipe unrolls it.
    $releases = Invoke-RestMethod -Uri $ReleasesApi -Headers $Headers -TimeoutSec 30 |
        ForEach-Object { $_ }
    $candidates = foreach ($release in $releases) {
        if ($release.draft -or $release.tag_name -notmatch $TagPattern) { continue }
        if ($SelectedChannel -eq 'stable' -and $release.prerelease) { continue }
        $asset = Get-InstallerAsset $release
        if ($asset) {
            [pscustomobject]@{ Release = $release; Asset = $asset }
        }
    }
    return @($candidates) |
        Sort-Object -Property { [datetime]$_.Release.published_at } -Descending |
        Select-Object -First 1
}

function Get-InstalledVersion {
    $found = foreach ($path in @($ProgramFilesExe, $PerUserExe)) {
        if (Test-Path -LiteralPath $path) {
            $text = (Get-Item -LiteralPath $path).VersionInfo.FileVersion
            $parsed = $null
            if ([version]::TryParse($text, [ref]$parsed)) { $parsed }
        }
    }
    return @($found) | Sort-Object -Descending | Select-Object -First 1
}

if (-not $Channel) { $Channel = Select-Channel }

Write-Host "Looking for the newest AtlasSOC $Channel version..."
$latest = Get-LatestInstaller $Channel
if (-not $latest) {
    if ($Channel -eq 'stable') {
        Write-Host 'No stable AtlasSOC release exists yet. Run this again and choose beta.'
    }
    else {
        Write-Host 'No AtlasSOC installer was found.'
    }
    exit 2
}

$asset = $latest.Asset
Write-Host "Found $($latest.Release.name)"

$installed = Get-InstalledVersion
if ($installed) {
    Write-Host "Installed version: $installed"
    if ($installed -ge $asset.Version -and -not $Force) {
        Write-Host 'You already have this version or a newer one. Use -Force to install anyway.'
        exit 0
    }
}

if ($asset.Digest -notmatch '^sha256:([0-9a-fA-F]{64})$') {
    throw 'GitHub did not report a SHA256 digest for this installer, so it cannot be verified.'
}
$expected = $Matches[1].ToUpperInvariant()

$folder = Join-Path $env:TEMP 'AtlasSOC-Update'
New-Item -ItemType Directory -Path $folder -Force | Out-Null
$target = Join-Path $folder $asset.Name

Write-Host "Downloading $($asset.Name)..."
Invoke-WebRequest -Uri $asset.Url -Headers @{ 'User-Agent' = $Headers['User-Agent'] } `
    -OutFile $target -UseBasicParsing -TimeoutSec 300

$actual = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
if ($actual -ne $expected) {
    Remove-Item -LiteralPath $target -Force
    throw "Checksum mismatch. Expected $expected but got $actual. The file was deleted."
}
Write-Host "Checksum OK: $actual"

if ($DownloadOnly) {
    Write-Host "Downloaded to $target"
    exit 0
}

if ($WaitPid -gt 0) {
    Write-Host 'Waiting for AtlasSOC to close...'
    Wait-Process -Id $WaitPid -Timeout 30 -ErrorAction SilentlyContinue
}

Write-Host 'Starting the installer. Windows may warn because the file is unsigned.'
$arguments = @()
if ($Silent) {
    # Inno Setup refuses to change scope, so stay in the scope that is installed now.
    $scope = if (Test-Path -LiteralPath $ProgramFilesExe) { '/ALLUSERS' } else { '/CURRENTUSER' }
    $arguments = @('/SILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/CLOSEAPPLICATIONS', $scope)
}
$start = @{ FilePath = $target; PassThru = $true; Wait = $true }
if ($arguments.Count -gt 0) { $start.ArgumentList = $arguments }
$process = Start-Process @start
if ($process.ExitCode -ne 0) {
    throw "The installer ended with code $($process.ExitCode). The installed version was kept."
}
Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
if ($Silent) { Start-AtlasSOC }
Write-Host 'Done.'
