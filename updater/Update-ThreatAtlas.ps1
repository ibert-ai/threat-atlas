# Installed by the per-user MSI. No administrator privileges or execution-policy bypass.
param([ValidateSet('Enable','Disable','Check')][string]$Mode = 'Check')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$install = Join-Path $env:LOCALAPPDATA 'ThreatAtlas'
$saver = Join-Path $install 'ThreatAtlas.scr'
$taskName = 'ThreatAtlas-Update-' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$log = Join-Path $install 'update-status.txt'
function Trusted-Signature([string]$path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    if ($signature.Status -ne 'Valid' -or !$signature.SignerCertificate) { throw 'A trusted code signature is required; unsigned previews cannot auto-update.' }
    return $signature.SignerCertificate
}
function Stable-Version([string]$tag) {
    if ($tag -notmatch '^v?(\d+)\.(\d+)\.(\d+)$') { throw 'Expected a stable major.minor.patch version.' }
    return [version]($tag.TrimStart('v'))
}
try {
    if ($Mode -eq 'Disable' -or !(Test-Path -LiteralPath $saver)) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        exit 0
    }
    # A PS7 caller can pass a module search path containing incompatible PS7 modules to PS5.1.
    # Load Authenticode from this host's own trusted installation instead of that inherited path.
    Import-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
    $publisher = Trusted-Signature $saver
    if ($Mode -eq 'Enable') {
        $script = Join-Path $install 'Update-ThreatAtlas.ps1'
        # Keep a tiny bootstrap in the task so uninstall can clean up even after this script is removed.
        $quotedScript = $script.Replace("'", "''")
        $quotedTask = $taskName.Replace("'", "''")
        $bootstrap = "if (Test-Path -LiteralPath '$quotedScript') { & '$quotedScript' -Mode Check } else { Unregister-ScheduledTask -TaskName '$quotedTask' -Confirm:`$false -ErrorAction SilentlyContinue }"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
        $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $encoded"
        $trigger = New-ScheduledTaskTrigger -Daily -At '12:00'
        $principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        'Automatic updates enabled. Stable releases are checked daily while signed in.' | Set-Content $log
        exit 0
    }
    $mutex = New-Object Threading.Mutex($false, ('Local\' + $taskName))
    if (!$mutex.WaitOne(0)) { exit 0 }
    try {
        # Never replace a running screen saver or disturb a locked session.
        if (Get-Process -Name 'ThreatAtlas' -ErrorAction SilentlyContinue) { exit 0 }
        $headers = @{ 'User-Agent' = 'ThreatAtlas-Updater'; 'Accept' = 'application/vnd.github+json' }
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $release = Invoke-RestMethod 'https://api.github.com/repos/ibert-ai/threat-atlas/releases/latest' -Headers $headers -TimeoutSec 30
        if ($release.draft -or $release.prerelease) { throw 'Only stable public releases are accepted.' }
        $version = Stable-Version $release.tag_name
        $current = Stable-Version ((Get-ItemProperty 'HKCU:\Software\Ibert Consulting\ThreatAtlas').DocsVersion)
        if ($version -le $current) { 'Already up to date.' | Set-Content $log; exit 0 }
        $name = "ThreatAtlas-$version-x64.msi"
        $assets = @($release.assets | Where-Object { $_.name -ceq $name })
        if ($assets.Count -ne 1 -or $assets[0].size -gt 104857600) { throw 'Missing or oversized signed MSI.' }
        $url = [uri]$assets[0].browser_download_url
        if ($url.Scheme -ne 'https' -or $url.Host -ne 'github.com' -or !$url.AbsolutePath.StartsWith('/ibert-ai/threat-atlas/releases/download/')) { throw 'Unexpected download URL.' }
        $stage = Join-Path $env:LOCALAPPDATA ('ThreatAtlas-update-' + [guid]::NewGuid())
        New-Item -ItemType Directory $stage | Out-Null
        try {
            $msi = Join-Path $stage $name
            Invoke-WebRequest $url.AbsoluteUri -OutFile $msi -Headers $headers -TimeoutSec 120 -UseBasicParsing
            if ((Get-Item $msi).Length -ne $assets[0].size) { throw 'Incomplete download.' }
            $candidate = Trusted-Signature $msi
            # Pin the installed signer's key. Certificate/key rotation requires an explicit manual upgrade.
            if ($candidate.GetPublicKeyString() -cne $publisher.GetPublicKeyString()) { throw 'Update publisher key differs from the installed trusted version.' }
            $installer = New-Object -ComObject WindowsInstaller.Installer
            $database = $installer.OpenDatabase($msi, 0)
            foreach ($property in @(@('ProductVersion', "$version"), @('UpgradeCode', '{9D690E47-8F57-4B7C-BB7E-C9DA787FE981}'))) {
                $query = "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='" + $property[0] + "'"
                $view = $database.OpenView($query); $view.Execute(); $row = $view.Fetch()
                if (!$row -or $row.StringData(1) -ine $property[1]) { throw 'Unexpected MSI product identity or version.' }
                $view.Close()
            }
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
            if (Get-Process -Name 'ThreatAtlas' -ErrorAction SilentlyContinue) { exit 0 }
            $process = Start-Process "$env:SystemRoot\System32\msiexec.exe" -ArgumentList "/i `"$msi`" /qn /norestart" -Wait -PassThru
            if ($process.ExitCode -notin 0,3010) { throw "Update failed: MSI exit $($process.ExitCode)." }
            "Updated to $version. Screen saver and lock settings were preserved." | Set-Content $log
        } finally { Remove-Item -LiteralPath $stage -Recurse -Force }
    } finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
} catch {
    if (Test-Path $install) { $_.Exception.Message | Set-Content $log }
    Write-Error $_
    exit 1
}
