<#
Sign (or only verify) the Windows files of one release, in the order given, and print a report.

Signing uses the certificate in the current user's store (Certum SimplySign Desktop must be logged in by
the owner first; see docs/SIGNING-CERTUM.md). No key, password or one-time code is read or stored here.

Examples (PowerShell on the signing PC):
  .\scripts\sign-release-windows.ps1 -Thumbprint <40 hex> -File .\dist\ThreatAtlas.scr,.\dist\AtlasSOC.exe
  .\scripts\sign-release-windows.ps1 -VerifyOnly -File .\dist\ThreatAtlas.msi

Status: written 14 Nov 2026 and NOT yet run against a real certificate. Do the first run on copies of test
files and record the result in docs/SIGNING-CERTUM.md.
#>
param(
    [ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$Thumbprint,
    [Parameter(Mandatory=$true)][string[]]$File,
    [string]$TimestampUrl = 'http://time.certum.pl',
    # Text that must appear in the signer subject, for example the name on the certificate. Optional.
    [string]$ExpectedSubject = '',
    [switch]$VerifyOnly
)
$ErrorActionPreference = 'Stop'

if (-not $VerifyOnly -and -not $Thumbprint) { throw 'Give -Thumbprint, or use -VerifyOnly.' }

$paths = foreach ($f in $File) {
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { throw "File not found: $f" }
    (Resolve-Path -LiteralPath $f).Path
}

$rows = @()
foreach ($p in $paths) {
    if (-not $VerifyOnly) {
        & (Join-Path $PSScriptRoot 'sign-windows.ps1') -Thumbprint $Thumbprint -File $p -TimestampUrl $TimestampUrl
    }
    $sig = Get-AuthenticodeSignature -LiteralPath $p
    $problems = @()
    if ($sig.Status -ne 'Valid') { $problems += "status $($sig.Status)" }
    if (-not $sig.TimeStamperCertificate) { $problems += 'no timestamp' }
    if ($Thumbprint -and $sig.SignerCertificate -and $sig.SignerCertificate.Thumbprint -ne $Thumbprint.ToUpperInvariant()) {
        $problems += 'signed by a different certificate'
    }
    if ($ExpectedSubject -and (-not $sig.SignerCertificate -or $sig.SignerCertificate.Subject -notlike "*$ExpectedSubject*")) {
        $problems += "signer subject does not contain '$ExpectedSubject'"
    }
    $rows += [pscustomobject]@{
        File    = Split-Path -Leaf $p
        Status  = if ($problems.Count) { 'FAIL' } else { 'OK' }
        Signer  = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
        SHA256  = (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLowerInvariant()
        Problem = ($problems -join '; ')
    }
}

$rows | Format-List
if ($rows | Where-Object { $_.Status -ne 'OK' }) { throw 'One or more files are not correctly signed.' }
Write-Host "All $($rows.Count) file(s) signed and verified. Copy this report into the release notes; do not skip the clean-account install check."
