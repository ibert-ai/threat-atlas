# Screensaver 0.5.0: what must be true before the Beta pre-release (SP9)

Written 17 November 2026 by CL. Nothing here is published. Status is what the repository and the private handovers show
today; a line turns green only with evidence recorded in the handover or `QUALITY.md`.

| Gate | Needed | State |
| --- | --- | --- |
| Core: shared view, settings reader, worker interface (SP1-SP3) | merged, CI green, independent review | **Done** (PR 103, 106, 107) |
| Windows host (SP4) | merged, CI green, review | **Done** (PR 108); not yet run on a real PC |
| macOS host (SP5) | MAC builds, signs, notarises, tests in System Settings preview and real idle | **Open**, MAC in progress |
| Privacy, consent and attribution texts (SP7) | texts merged; Radar not claimed; qualified review of consent wording (R2) | **Open**, Seek |
| Tests (SP8) | multi-monitor, idle and lock, CPU/memory within +25 % of 0.4.8, mixed DPI, 30 min soak; one result line per case | **Open**, Billy (Windows), MAC (macOS) |
| Optimisation and hardening round | baseline and after numbers, unsafe audit, fuzz/property tests, CI on the exact commit, MAC review | **Open** |
| Documentation gate | feature text, `PRIVACY.md`, `THIRD-PARTY-NOTICES.txt`, version map, changelog, release notes, README | **Started** (this file and `VERSION-FEATURES.md`) |
| Beta channel feed | signed feed entry on the Beta channel (UPDATE-CHANNELS WP) | **Open**, not built |
| Windows signing | Certum certificate | **Open**, order under processing; packages stay unsigned and say so |
| Owner decision | Robert says go for a Beta pre-release | **Open** |

## Multi-monitor tests (SP8)

The standard saver draws on the display Windows starts it on; panorama spans two matching adjacent displays and keeps the
classic view. Tests that need two displays run on the dual-display PC (two 1920x1080 side by side) and on the second test
PC with two different refresh rates. The 0.4.8 saver is the baseline; `ATLAS_SAVER_CLASSIC=1` runs the classic view in the
new build for a like-for-like comparison. Each case reports OK, Warning or Error.

## Not done by this file

No version number is bumped, no package is built, no tag or release is created.
