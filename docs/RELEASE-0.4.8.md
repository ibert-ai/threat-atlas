# Threat Atlas screensaver 0.4.8 — published stable, build 16

Published 11 November 2026 from `7fba1cc1b3c0b7cdc295d67d4bff378d6d46fff4`.
[Release notes and downloads](https://github.com/ibert-ai/threat-atlas/releases/tag/v0.4.8).

## Identity and packages

| Item | Published record |
|---|---|
| Screensaver | 0.4.8, build 16, tag `v0.4.8`, stable |
| Windows 10/11 x64 | All-users MSI and portable ZIP; unsigned |
| macOS 12+, Apple silicon / Intel | Developer ID signed, notarized and stapled ZIP |
| Linux x86_64 | Windowed preview archive; no idle/lock integration |
| Related Desktop stable | 0.7.0, build 13, tag `atlassoc-v0.7.0`, same source |
| Later Desktop Linux preview | Build 13, tag `atlassoc-v0.7.0-linux`, newer source `c8256318285e24cd8f794be01edff0a802276bc5`; published 12 November |

## What changed

Promotes the 0.4.7-rc.1 panorama implementation. Classic appearance is unchanged
and pinned by a regression test. The numeric version advances for MSI upgrade
identity. Seeker code is present but not selectable in release builds.
The lockfile updates rustix to 1.1.6; release notes state it is not compiled
into these platform packages. Desktop includes the macOS `APPL` bundle-type fix.

## Verification and limits

The published notes report successful hosted Windows/MSI checks and macOS
signature/notarization checks. This documentation pass independently checked
the release metadata, asset inventory and source; it did not download or execute
the packages or repeat signing checks.

Not re-tested on physical hardware for these exact packages: Windows
install/upgrade, idle start, lock-on-resume, 150/200% scaling, mixed DPI/hot-plug,
physical ultrawide and Intel Mac. Linux remains a windowed preview with no
physical desktop acceptance. DNS can delay feed shutdown. Stable is the
maintainer's release decision, not a claim that these gaps passed.

## Package verification

Use the release's SHA-256 files before installation. The macOS ZIP has a
separate signed-package checksum file. Existing release assets remain unchanged.
See [known bugs and limitations](KNOWN-BUGS.md), the
[Desktop stable release](https://github.com/ibert-ai/threat-atlas/releases/tag/atlassoc-v0.7.0)
and [Linux Desktop preview](ATLAS-SOC-LINUX.md).
