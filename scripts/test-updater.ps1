# Offline tests on a disposable Windows runner. No tasks or network access expected.
$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot '../updater/Update-ThreatAtlas.ps1'
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('ThreatAtlas-test-' + [guid]::NewGuid())
# Load the real version parser without running the updater's platform side effects.
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($script, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Stable-Version' }, $true)
. ([scriptblock]::Create($definition.Extent.Text))
if ((Stable-Version 'v1.10.0') -le (Stable-Version '1.9.0')) { throw 'Version ordering failed' }
foreach ($invalid in 'v1.0.0-rc.1', '1.2', '../1.0.0', '1.0.0.1') {
    $rejected = $false
    try { [void](Stable-Version $invalid) } catch { $rejected = $true }
    if (!$rejected) { throw "Accepted invalid version: $invalid" }
}
$originalLocalAppData = $env:LOCALAPPDATA
try {
    $env:LOCALAPPDATA = $fixture
    $install = Join-Path $fixture 'ThreatAtlas'
    New-Item -ItemType Directory $install -Force | Out-Null
    Set-Content (Join-Path $install 'ThreatAtlas.scr') 'unsigned test fixture; never executed'
    foreach ($hostExe in 'powershell.exe', 'pwsh.exe') {
        $out = Join-Path $fixture 'stdout.txt'; $err = Join-Path $fixture 'stderr.txt'
        $process = Start-Process $hostExe -ArgumentList "-NoProfile -NonInteractive -File `"$script`" -Mode Enable" -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
        $statusFile = Join-Path $install 'update-status.txt'
        $status = if (Test-Path $statusFile) { Get-Content $statusFile -Raw } else { '<no status file>' }
        if ($process.ExitCode -eq 0 -or $status -notmatch 'trusted code signature') {
            throw "${hostExe}: unsigned rejection failed. Status: $status Output: $(Get-Content $out -Raw) Error: $(Get-Content $err -Raw)"
        }
    }
} finally {
    $env:LOCALAPPDATA = $originalLocalAppData
    Remove-Item $fixture -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host 'Unsigned updates rejected under Windows PowerShell 5.1 and PowerShell 7.'
