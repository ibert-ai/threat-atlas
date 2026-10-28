$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
cargo build --locked --release --target x86_64-pc-windows-msvc -p threat-atlas
if ($LASTEXITCODE -ne 0) { throw "Rust build failed" }
New-Item -ItemType Directory -Force dist | Out-Null
Copy-Item target/x86_64-pc-windows-msvc/release/threat-atlas.exe dist/ThreatAtlas.scr
Write-Host "Built dist/ThreatAtlas.scr. Right-click and choose Install."
