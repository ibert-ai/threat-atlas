# Offline tests on a disposable Windows runner. No tasks or network access expected.
$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot '../updater/Update-ThreatAtlas.ps1'
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('ThreatAtlas-test-' + [guid]::NewGuid())
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
