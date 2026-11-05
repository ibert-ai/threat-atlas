param([string]$Compiler = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", [string]$Version, [int]$Build)
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$package = Join-Path $PWD 'dist/windows-soc'
if (-not (Test-Path -LiteralPath (Join-Path $package 'AtlasSOC.exe'))) { throw 'Run build-windows-soc.ps1 first.' }
if (-not (Test-Path -LiteralPath $Compiler)) { throw "Inno Setup compiler not found: $Compiler" }
$identity = Get-Content -Raw -LiteralPath 'windows-soc-version.json' | ConvertFrom-Json
# A version override exists only to build a later test package for upgrade checks.
if ($Version) { $identity.version = $Version; $identity.build = $Build }
$output = Join-Path $PWD 'dist'
& $Compiler "/DAppVersion=$($identity.version)" "/DAppBuild=$($identity.build)" "/DPackageDirectory=$package" "/DOutputDirectory=$output" "/DSourceRoot=$PWD" 'installer/AtlasSOC.iss'
if ($LASTEXITCODE) { throw 'Installer build failed' }
Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $output "AtlasSOC-Setup-$($identity.version)-build$($identity.build).exe")
Write-Output 'Built the AtlasSOC installer. Nothing was installed or published.'
