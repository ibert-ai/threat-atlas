# SOC Desktop parity and preservation checklist

Reference SOC-DESKTOP-NEXT-20261104-01. Baseline: Desktop 0.7.0 build 10 (`2260a27c`), stable screensaver 0.4.5 build 13 (`ce986195`). Status means source state, not package acceptance.

## Stable screensaver features

| Feature | Status | Desktop action |
|---|---|---|
| GreyNoise records, bounded buffers, LIVE/STALE/OFFLINE, reconnect | Shared core | Test on the final package |
| UTC and local clocks | Shared | Test timezone and DST on the final package |
| Country borders, classification colours, high-volume retention | Shared | Test on the final package |
| Installed version on the main view | Fixed here | Desktop footer now reads `atlassoc-beta-version.json`; screensaver footer unchanged |
| Windows scaling, layout, resizing | Desktop host exists | Test at 100, 150 and 200% DPI, portrait, ultrawide and tiny windows |
| Installer lifecycle | Review build | `installer/AtlasSOC.iss`; test with `scripts/test-windows-soc-installer.ps1` |
| Versioned packages, checksums, exact-source tests | To implement | New Desktop identity from MAC |
| Safe manual updates | Already true | Keep; no updater, startup task or schedule |
| Linux preview | Later phase | Not in the Windows phase |
| System32 SCR, idle and lock integration, Mac saver | Screensaver only | Desktop must coexist; it never installs to System32 or changes idle, lock or password settings |

## Desktop features that must remain

- Realtime (default), Calm and Still; freeze with the feed continuing; bounded motion.
- Severity filters; country hover, inspection and focus; record list; counters; rate chart; timestamps and provider meaning.
- Saved window size, fullscreen, always-on-top, keyboard and help, mirroring with one feed, monitor changes, reset.
- Radar: aggregate view, OS credential store token (Keychain, Credential Manager), attribution, consent identity, cache, 15-minute floor, cooldown, backoff, single worker. Windows Radar added at the owner's request on 5 November 2026.
- Current icon, separate settings, portable use and rollback, privacy, verified TLS.

## Not part of this phase

SOC wall roles and spanning, Zero Wire, signing, trusted updates, and physical multi-monitor or soak testing stay listed as open work.
