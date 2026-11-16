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
try { & $script -FeedFile $feed -ResolveOnly | Out-Null; Write-Host 'FAIL: ran without -AllowUnsignedFeed'; $failed++ } catch { }
$bad = Get-Content -LiteralPath $feed -Raw | ConvertFrom-Json
foreach ($a in $bad.products.atlassoc.releases[0].assets) { $a.url = 'https://evil.example/x.exe' }
$badFile = Join-Path ([IO.Path]::GetTempPath()) 'bad-feed.json'
$bad | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $badFile -Encoding UTF8
try { & $script -Product atlassoc -Channel beta -FeedFile $badFile -ResolveOnly -AllowUnsignedFeed | Out-Null; Write-Host 'FAIL: accepted a foreign URL'; $failed++ } catch { }
Remove-Item -LiteralPath $badFile -ErrorAction SilentlyContinue
if ($failed) { throw "$failed get-latest.ps1 test(s) failed" }
Write-Host "get-latest.ps1: $($cases.Count) resolution cases and 2 refusal cases passed."
