#requires -Version 5.1
# Offline test: get-latest.ps1 must resolve every case in scripts/fixtures/update-feed-cases.json exactly
# like the Python resolver (scripts/update_feed.py), refuse to run without -AllowUnsignedFeed, and refuse
# a feed whose URL is outside the project's GitHub releases.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSCommandPath
$script = Join-Path $root 'get-latest.ps1'
$feed = Join-Path $root 'fixtures\update-feed-sample.json'
$cases = (Get-Content -LiteralPath (Join-Path $root 'fixtures\update-feed-cases.json') -Raw | ConvertFrom-Json).cases
$failed = 0
foreach ($c in $cases) {
    try {
        $r = & $script -Product $c.product -Channel $c.channel -Platform $c.platform -FeedFile $feed -ResolveOnly -AllowUnsignedFeed | ConvertFrom-Json
        if ($r.version -ne $c.version -or $r.name -ne $c.asset) { throw "got $($r.version) / $($r.name)" }
    } catch { Write-Host "FAIL $($c.product) $($c.channel) $($c.platform): $_"; $failed++ }
}
function Assert-Refuses([scriptblock]$Run, [string]$Pattern, [string]$What) {
    $threw = $false
    try { & $Run | Out-Null } catch { $threw = $true; if ($_.Exception.Message -notmatch $Pattern) { Write-Host "FAIL ${What}: refused for another reason: $($_.Exception.Message)"; $script:failed++; return } }
    if (-not $threw) { Write-Host "FAIL: $What"; $script:failed++ }
}
Assert-Refuses { & $script -FeedFile $feed -ResolveOnly } 'Feed signature' 'ran without -AllowUnsignedFeed'
$bad = Get-Content -LiteralPath $feed -Raw | ConvertFrom-Json
foreach ($a in $bad.products.atlassoc.releases[0].assets) { $a.url = 'https://evil.example/x.exe' }
$dots = Get-Content -LiteralPath $feed -Raw | ConvertFrom-Json
foreach ($a in $dots.products.atlassoc.releases[0].assets) { $a.url = 'https://github.com/Ibert-Iam/threat-atlas/releases/download/../../../evil/x/' + $dots.products.atlassoc.releases[0].tag + '/' + $a.name }
$dotsFile = Join-Path ([IO.Path]::GetTempPath()) 'dots-feed.json'
$dots | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $dotsFile -Encoding UTF8
$badFile = Join-Path ([IO.Path]::GetTempPath()) 'bad-feed.json'
$bad | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $badFile -Encoding UTF8
Assert-Refuses { & $script -Product atlassoc -Channel beta -FeedFile $badFile -ResolveOnly -AllowUnsignedFeed } 'outside the project' 'accepted a foreign URL'
Assert-Refuses { & $script -Product atlassoc -Channel beta -FeedFile $dotsFile -ResolveOnly -AllowUnsignedFeed } 'outside the project' 'accepted a dot-dot URL'
# -Kind installer must return an installer file.
$r = & $script -Product atlassoc -Channel beta -Platform windows-x64 -Kind installer -FeedFile $feed -ResolveOnly -AllowUnsignedFeed | ConvertFrom-Json
if ($r.name -notmatch 'Setup') { Write-Host "FAIL: -Kind installer returned $($r.name)"; $failed++ }
Remove-Item -LiteralPath $badFile, $dotsFile -ErrorAction SilentlyContinue
if ($failed) { throw "$failed get-latest.ps1 test(s) failed" }
Write-Host "get-latest.ps1: $($cases.Count) resolution cases and 4 refusal cases passed."
