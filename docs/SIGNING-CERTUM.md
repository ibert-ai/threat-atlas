# Windows signing with Certum Open Source Code Signing in the Cloud

Status: **prepared, not yet used.** No certificate exists until the owner has bought, verified and
activated it. Nothing below has been run against a real Certum certificate; the first real signing
must be done step by step and the results recorded.

## What the certificate is

- Issued to the owner as a natural person; the certificate shows his name with the phrase
  "Open Source Developer". It does not show Ibert Consulting.
- Cloud-stored (SimplySign): there is no card. A Windows computer connects to a virtual card with
  the SimplySign Desktop application; the owner's phone app shows a one-time code for each login.
- Limit: 5000 signatures per month (Certum shop, November 2026). A release signs well under 20 files.
- Certum revokes the certificate if it is used for commercially distributed software. Keep the
  software free to use, and say so in the README and the release notes.
- The project must be public and show who maintains it: README "Maintainer" section.

## Who does what

| Step | Who |
|---|---|
| Buy, identity check, activate the certificate, install the SimplySign phone app | Owner only |
| Log in to SimplySign Desktop on the signing PC (enter the one-time code) | Owner only |
| Build packages, run the signing script, verify, publish | CL, or MAC with the owner's go |

The one-time codes, the SimplySign login and any recovery or seed value are never typed into chat,
Git, logs or command arguments. No automation of the login (for example a stored authenticator
secret in CI) is allowed without a separate written owner decision.

## One-time setup on the signing PC (Windows 10/11)

1. Install the Windows SDK signing tools (`signtool.exe`) and Certum SimplySign Desktop.
2. Owner logs in to SimplySign Desktop (account email and the code from the phone app). The
   certificate then appears in the current user's certificate store ("My").
3. List it and note the thumbprint (40 hex characters; it is public, not secret):
   `certutil -user -store My`
4. Do a dry run on a copy of a test file first.

## Signing a release

Use the existing script, one file per call. It signs with SHA-256, adds an RFC 3161 timestamp and
verifies the result:

```powershell
.\scripts\sign-windows.ps1 -Thumbprint <THUMBPRINT> -File <file>
# Certum's own timestamp server can be used instead of the default:
.\scripts\sign-windows.ps1 -Thumbprint <THUMBPRINT> -File <file> -TimestampUrl http://time.certum.pl
```

Files to sign, in this order, per release:

1. Screensaver: `ThreatAtlas.scr` from the Windows build (before it goes into the MSI or the ZIP).
2. Screensaver MSI, after it has been built with the signed SCR.
3. AtlasSOC: `AtlasSOC.exe` (`scripts/build-windows-soc.ps1` signs it when `ATLAS_SIGN_THUMBPRINT`
   is set), then the installer `AtlasSOC-Setup-<version>-build<n>.exe`.

Open points that must be settled before the first signed release:

- The MSI is built on Linux/macOS (`scripts/build-msi.sh`) from the Windows binary. A signed SCR
  inside the MSI therefore needs: sign the SCR on Windows, build the MSI with that SCR, sign the MSI
  on Windows. The CI `msi` job does not do this today.
- The AtlasSOC installer build in CI does not sign the installer itself.
- Published assets are never overwritten. Signed packages are a new version with new checksums,
  new release notes and a new tag; the old unsigned versions stay available.
- Signing does not give instant SmartScreen reputation; say so in the release notes.

## After signing

1. `signtool verify /pa /all /v <file>` (the script already does this).
2. Install on a clean Windows account and check the publisher shown by Windows.
3. Record in the release notes: signed by "Open Source Developer" certificate from Certum,
   timestamped, and which files are signed.
4. Remove "Windows packages are unsigned" wording only for files that really are signed.
