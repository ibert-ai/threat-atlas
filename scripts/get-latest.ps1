<#
.SYNOPSIS
    Downloads the newest Threat Atlas / AtlasSOC file for an update channel and verifies its SHA-256.

.DESCRIPTION
    Windows PowerShell 5.1 or newer. Reads the update feed (docs/UPDATE-CHANNELS.md), applies the
    channel fallback (Beta -> RC -> Stable, RC -> Stable), downloads only from the project's GitHub
    releases and checks the size and SHA-256 from the feed. The installer is started only with
    -Install, and then it stays the normal interactive installer: you approve any Windows prompt.

.PARAMETER Product     atlassoc (default) or screensaver.
.PARAMETER Channel     stable (default), rc or beta.
.PARAMETER Platform    windows-x64 (default).
.PARAMETER Kind        auto (installer, else portable), installer or portable.
.PARAMETER FeedUrl     https URL of the feed (default: the project's update-feed branch).
.PARAMETER FeedFile    Local feed file (tests and offline use).
.PARAMETER OutDir      Download folder (default: %TEMP%\ThreatAtlas-Download).
.PARAMETER ResolveOnly Print the resolved version and file as JSON and stop.
.PARAMETER Install     Start the downloaded installer (.exe/.msi) after verification.
.PARAMETER AllowUnsignedFeed
    Required until feed signatures exist. The file is then protected by its SHA-256 from the feed
    only; also check the Authenticode signature when the release is signed.

.EXAMPLE
    .\get-latest.ps1 -Channel rc -AllowUnsignedFeed
#>
[CmdletBinding()]
param(
    [ValidateSet('atlassoc', 'screensaver')][string]$Product = 'atlassoc',
    [ValidateSet('stable', 'rc', 'beta')][string]$Channel = 'stable',
    [string]$Platform = 'windows-x64',
    [ValidateSet('auto', 'installer', 'portable')][string]$Kind = 'auto',
    [string]$FeedUrl = 'https://raw.githubusercontent.com/ibert-ai/threat-atlas/update-feed/feed.json',
    [string]$FeedFile,
    [string]$OutDir = (Join-Path $env:TEMP 'ThreatAtlas-Download'),
    [switch]$ResolveOnly,
    [switch]$Install,
    [switch]$AllowUnsignedFeed
)
$ErrorActionPreference = 'Stop'
$DownloadPrefix = 'https://github.com/ibert-ai/threat-atlas/releases/download/'
$Allowed = @{ stable = @('stable'); rc = @('stable', 'rc'); beta = @('stable', 'rc', 'beta') }

function Get-VersionKey([string]$Version) {
    # Pre-release sorts below its release: beta < rc < final.
    if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)(?:-(beta|rc)\.(\d+))?$') { throw "Bad version: $Version" }
    $rank = switch ($Matches[4]) { 'beta' { 0 } 'rc' { 1 } default { 2 } }
    $num = if ($Matches[5]) { [int]$Matches[5] } else { 0 }
    return @([int]$Matches[1], [int]$Matches[2], [int]$Matches[3], $rank, $num)
}
function Test-VersionNewer([string]$A, [string]$B) {
    $ka = Get-VersionKey $A; $kb = Get-VersionKey $B
    for ($i = 0; $i -lt 5; $i++) { if ($ka[$i] -ne $kb[$i]) { return $ka[$i] -gt $kb[$i] } }
    return $false
}
function Resolve-Release($Block, [string]$Ch, [string]$Plat) {
    $best = $null
    $withdrawn = @($Block.withdrawn)
    foreach ($rel in $Block.releases) {
        if ($withdrawn -contains $rel.version) { continue }
        if ($Allowed[$Ch] -notcontains $rel.channel) { continue }
        $hasPlatform = @($rel.assets | Where-Object { $_.platform -eq $Plat -and $_.kind -ne 'checksums' }).Count -gt 0
        if (-not $hasPlatform) { continue }
        if ($null -eq $best -or (Test-VersionNewer $rel.version $best.version)) { $best = $rel }
    }
    return $best
}
function Select-Asset($Release, [string]$Plat, [string]$WantedKind) {
    $kinds = if ($WantedKind -eq 'auto') { @('installer', 'portable') } else { @($WantedKind) }
    foreach ($k in $kinds) {
        $a = $Release.assets | Where-Object { $_.platform -eq $Plat -and $_.kind -eq $k } | Select-Object -First 1
        if ($a) { return $a }
    }
    return $null
}

if (-not $AllowUnsignedFeed) {
    throw 'Feed signature checking is not implemented yet. Re-run with -AllowUnsignedFeed to continue with SHA-256 only.'
}
if ($FeedFile) {
    $raw = Get-Content -LiteralPath $FeedFile -Raw -Encoding UTF8
} else {
    if ($FeedUrl -notmatch '^https://') { throw 'The feed URL must be https.' }
    $raw = (Invoke-WebRequest -Uri $FeedUrl -UseBasicParsing -TimeoutSec 30).Content
    if ($raw -is [byte[]]) { $raw = [System.Text.Encoding]::UTF8.GetString($raw) }
}
if ($raw.Length -gt 1000000) { throw 'The feed is too large.' }
$feed = $raw | ConvertFrom-Json
if ($feed.schema_version -ne 1) { throw 'Unsupported feed schema.' }
$block = $feed.products.$Product
if ($null -eq $block) { throw "The feed has no product '$Product'." }

$release = Resolve-Release $block $Channel $Platform
if ($null -eq $release) { throw "No release available for $Product / $Channel / $Platform." }
$asset = Select-Asset $release $Platform $Kind
if ($null -eq $asset) { throw "No $Kind file for $Platform in $($release.version)." }
if (-not $asset.url.StartsWith($DownloadPrefix)) { throw 'Refusing a download URL outside the project''s GitHub releases.' }
if ($asset.name -notmatch '^[A-Za-z0-9._-]+$') { throw 'Refusing an unsafe file name.' }
if ($asset.sha256 -notmatch '^[0-9a-f]{64}$') { throw 'The feed has a bad SHA-256 for this file.' }

$result = [ordered]@{ product = $Product; channel = $Channel; version = $release.version; released_as = $release.channel
    name = $asset.name; url = $asset.url; sha256 = $asset.sha256; size = $asset.size }
if ($ResolveOnly) { $result | ConvertTo-Json; return }

Write-Host "Channel $Channel -> $Product $($release.version) ($($release.channel)), $($asset.name)"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$dest = Join-Path $OutDir $asset.name
$part = "$dest.part"
Invoke-WebRequest -Uri $asset.url -OutFile $part -UseBasicParsing -TimeoutSec 600
if ((Get-Item -LiteralPath $part).Length -ne [int64]$asset.size) { Remove-Item -LiteralPath $part; throw 'Size differs from the feed; file removed.' }
$got = (Get-FileHash -LiteralPath $part -Algorithm SHA256).Hash.ToLowerInvariant()
if ($got -ne $asset.sha256) { Remove-Item -LiteralPath $part; throw 'SHA-256 mismatch; file removed.' }
Move-Item -LiteralPath $part -Destination $dest -Force
Write-Host "SHA-256 verified: $got"
if ($Install -and $asset.name -match '\.(exe|msi)$') {
    Write-Host 'Starting the installer; approve any Windows prompt yourself.'
    Start-Process -FilePath $dest
} else {
    Write-Host 'Nothing was installed.'
}
Write-Host 'Unsigned feed: also check the Authenticode signature before you run a file.'
$dest
