param([string]$Binary = (Join-Path $PSScriptRoot '../dist/windows-soc/AtlasSOC.exe'))
$ErrorActionPreference = 'Stop'
$Binary = (Resolve-Path -LiteralPath $Binary).Path
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('ThreatAtlasSOC-Test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$report = Join-Path $testRoot 'native-smoke.json'
$consent = Join-Path $env:LOCALAPPDATA 'ThreatAtlasSOC/consent.json'
$before = if (Test-Path -LiteralPath $consent) { (Get-FileHash -LiteralPath $consent).Hash } else { 'absent' }
$native = Start-Process -FilePath $Binary -ArgumentList @('--smoke-test', ('"' + $report + '"')) -WindowStyle Hidden -PassThru
try {
    if (-not $native.WaitForExit(30000)) { throw 'Native offline smoke exceeded 30 seconds' }
    if ($native.ExitCode -ne 0) { throw "Native offline smoke failed: $($native.ExitCode)" }
    $result = Get-Content -Raw -LiteralPath $report | ConvertFrom-Json
    if (-not $result.offline_test -or $result.feed_constructed -or $result.consent_written -or $result.frames_presented -lt 2 -or $result.windows -ne 1 -or -not $result.sentinel_icon_loaded) { throw 'Invalid native smoke evidence or missing Sentinel icon resource' }
    $after = if (Test-Path -LiteralPath $consent) { (Get-FileHash -LiteralPath $consent).Hash } else { 'absent' }
    if ($before -ne $after) { throw 'Offline smoke modified real user consent' }
    Get-Content -LiteralPath $report
    Write-Output "PASS: native window/frame lifecycle; no feed constructed or user consent changed. Evidence: $report"
} finally {
    if (-not $native.HasExited) { Stop-Process -Id $native.Id }
}
