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
.PARAMETER OutDir      Download folder (default: %LOCALAPPDATA%\ThreatAtlas\Downloads, per user).
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
    [string]$FeedUrl = 'https://raw.githubusercontent.com/Ibert-Iam/threat-atlas/update-feed/feed.json',
    [string]$FeedFile,
    [string]$OutDir = (Join-Path $env:LOCALAPPDATA 'ThreatAtlas\Downloads'),
    [switch]$ResolveOnly,
    [switch]$Install,
    [switch]$AllowUnsignedFeed
)
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 may default to old TLS versions; GitHub needs TLS 1.2.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
$DownloadPrefix = 'https://github.com/Ibert-Iam/threat-atlas/releases/download/'
$Allowed = @{ stable = @('stable'); rc = @('stable', 'rc'); beta = @('stable', 'rc', 'beta') }

function Get-VersionKey([string]$Version) {
    # Pre-release sorts below its release: beta < rc < final.
    # No leading zeros (same rule as update_feed.py and the Rust core).
    if ($Version -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(beta|rc)\.(0|[1-9]\d*))?$') { throw "Bad version: $Version" }
    $rank = switch ($Matches[4]) { 'beta' { 0 } 'rc' { 1 } default { 2 } }
    $num = if ($Matches[5]) { [int]$Matches[5] } else { 0 }
    return @([int]$Matches[1], [int]$Matches[2], [int]$Matches[3], $rank, $num)
}
function Test-VersionNewer([string]$A, [string]$B) {
    $ka = Get-VersionKey $A; $kb = Get-VersionKey $B
    for ($i = 0; $i -lt 5; $i++) { if ($ka[$i] -ne $kb[$i]) { return $ka[$i] -gt $kb[$i] } }
    return $false
}
function Test-DownloadUrl([string]$Url, [string]$Name, $Release) {
    # Exact https://github.com/Ibert-Iam/threat-atlas/releases/download/<tag>/<name>; no '..', '%', '\', '@', '?', '#'.
    if ([string]::IsNullOrEmpty($Url) -or $Url -match '[\\%?#@\s]' -or $Url -match '(^|/)\.\.?(/|$)') { return $false }
    $u = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$u)) { return $false }
    if ($u.Scheme -ne 'https' -or $u.Host -ne 'github.com' -or -not $u.IsDefaultPort) { return $false }
    $parts = $u.AbsolutePath.Split('/')
    if ($parts.Count -ne 7 -or $parts[0] -ne '') { return $false }
    if ($parts[1] -cne 'Ibert-Iam' -or $parts[2] -cne 'threat-atlas' -or $parts[3] -cne 'releases' -or $parts[4] -cne 'download') { return $false }
    if ($parts[5] -cne $Release.tag -and $parts[5] -cne "$($Release.tag)-linux") { return $false }
    if ($parts[5] -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or $parts[6] -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { return $false }
    return ($parts[6] -ceq $Name)
}
function Resolve-Release($Block, [string]$Ch, [string]$Plat, [string]$WantedKind) {
    $best = $null
    $withdrawn = @($Block.withdrawn)
    foreach ($rel in $Block.releases) {
        if ($withdrawn -contains $rel.version) { continue }
        if ($Allowed[$Ch] -notcontains $rel.channel) { continue }
        if ($null -eq (Select-Asset $rel $Plat $WantedKind)) { continue }
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

$release = Resolve-Release $block $Channel $Platform $Kind
if ($null -eq $release) { throw "No release available for $Product / $Channel / $Platform." }
$asset = Select-Asset $release $Platform $Kind
if ($null -eq $asset) { throw "No $Kind file for $Platform in $($release.version)." }
if (-not (Test-DownloadUrl $asset.url $asset.name $release)) { throw 'Refusing a download URL outside the project''s GitHub releases.' }
if ($asset.name -notmatch '^[A-Za-z0-9._-]+$') { throw 'Refusing an unsafe file name.' }
if ($asset.sha256 -notmatch '^[0-9a-f]{64}$') { throw 'The feed has a bad SHA-256 for this file.' }

$result = [ordered]@{ product = $Product; channel = $Channel; version = $release.version; released_as = $release.channel
    name = $asset.name; url = $asset.url; sha256 = $asset.sha256; size = $asset.size }
if ($ResolveOnly) { $result | ConvertTo-Json; return }

Write-Host "Channel $Channel -> $Product $($release.version) ($($release.channel)), $($asset.name)"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if ((Get-Item -LiteralPath $OutDir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing a download folder that is a link.' }
$dest = Join-Path $OutDir $asset.name
if (Test-Path -LiteralPath $dest) { if ((Get-Item -LiteralPath $dest -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing to replace a link in the download folder.' } }
$part = Join-Path $OutDir ('{0}.{1}.part' -f $asset.name, [guid]::NewGuid().ToString('N'))
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
