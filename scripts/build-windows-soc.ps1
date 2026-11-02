param([string]$Python = 'python', [string]$Cargo = 'cargo')
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
& $Python scripts/version.py --check
if ($LASTEXITCODE) { throw 'Screensaver metadata mismatch' }
& $Python scripts/check-cloudflare-license.py
if ($LASTEXITCODE) { throw 'Cloudflare terms changed or unavailable; review required' }
& $Python scripts/check-source.py
if ($LASTEXITCODE) { throw 'Source scan failed' }
& $Cargo test --locked -p threat-atlas --bin threat-atlas-soc
if ($LASTEXITCODE) { throw 'Windows SOC regression tests failed' }
& $Cargo build --locked --release --target x86_64-pc-windows-msvc -p threat-atlas --bin threat-atlas-soc
if ($LASTEXITCODE) { throw 'Windows SOC build failed' }
$package = Join-Path $PWD 'dist/windows-soc'
New-Item -ItemType Directory -Force -Path $package | Out-Null
$targetRoot = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $PWD 'target' }
Copy-Item -LiteralPath (Join-Path $targetRoot 'x86_64-pc-windows-msvc/release/threat-atlas-soc.exe') -Destination (Join-Path $package 'AtlasSOC.exe')
Copy-Item -LiteralPath 'docs/WINDOWS-SOC.md','docs/ATLAS-SOC-BETA.md','LICENSE','PRIVACY.md','THIRD-PARTY-NOTICES.txt','docs/CLOUDFLARE-LICENSE.json' -Destination $package
$sourceCommit = (& git rev-parse HEAD).Trim()
$sourceDirty = [bool](& git status --porcelain --untracked-files=normal)
$socVersion = Get-Content -Raw -LiteralPath 'windows-soc-version.json' | ConvertFrom-Json
$iconHash = (Get-FileHash -Algorithm SHA256 -LiteralPath 'assets/atlassoc/sentinel/AtlasSOC.ico').Hash.ToLowerInvariant()
$expectedIconHash = (Get-Content -Raw -LiteralPath 'assets/atlassoc/sentinel/manifest.json' | ConvertFrom-Json).files.'AtlasSOC.ico'
if ($iconHash -ne $expectedIconHash) { throw 'Sentinel asset hash mismatch' }
$manifest = [ordered]@{product='AtlasSOC';publisher='Ibert Consulting';version=$socVersion.version;build=$socVersion.build;platform='windows-x64';source_commit=$sourceCommit;source_dirty=$sourceDirty;signature='unsigned';package='portable standalone beta; not a screensaver or MSI';radar_network='not implemented on Windows';sentinel_ico_sha256=$iconHash;sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $package 'AtlasSOC.exe')).Hash.ToLowerInvariant()}
$manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $package 'manifest.json') -Encoding utf8
$zip = Join-Path $PWD "dist/AtlasSOC-Windows-x64-v$($socVersion.version)-build$($socVersion.build).zip"
Compress-Archive -Path (Join-Path $package '*') -DestinationPath $zip -Force
Get-FileHash -Algorithm SHA256 -LiteralPath $zip,(Join-Path $package 'AtlasSOC.exe')
Write-Output 'Built standalone Windows SOC portable package. No installation, consent acceptance or release publication performed.'
