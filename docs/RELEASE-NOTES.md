# Threat Atlas screensaver 0.4.3-rc.1 — macOS beta

OS-by-OS publication authorized4 November2026. This first publication contains macOS only; Windows and Linux assets are not implied available or accepted. Existing releases are preserved.

Product0.4.3,build11. The macOS/core implementation is unchanged from the independently reviewed773a1062d270 source; this release advances package identity and records platform-specific acceptance. MSI proposal source in this branch is not a published Windows installer.

## Validation
Fresh exact-source universal macOS package,strict ad-hoc signatures,arm64/x86_64 slices,native CheckSaver rendering/lifecycle and offline updater security are validated separately for the final commit. Evidence accompanies downloads. Never treat checks for a prior package as a fresh run.

## Known issues and limits
Ad-hoc signed,not notarized:manual installation;Gatekeeper policy applies. No new physical Intel,System Settings installation,real idle/lock,multi-monitor/HiDPI or extended soak acceptance is claimed. OS DNS resolution may delay feed-worker shutdown. A legacy0.2 saver may remain selected;select Threat Atlas SOC and reopen Settings. Automatic updater signature/prerelease restrictions remain.

Linux preview remains at its existing beta while follow-up is tracked in https://github.com/ibert-ai/threat-atlas/issues/25 . No Linux binary is included in this publication. Windows publication requires its own exact-version evidence;no Windows result is inferred from Mac tests.
