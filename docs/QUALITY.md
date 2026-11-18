# Quality and security review — 28 October 2026

Original review: 0.3.0; updated for published 0.4.0 and the 0.4.1 development line. This is a source review and automated checks,
not an independent penetration test or a guarantee that no bugs remain.

## Fixed in this review

- Remote intention strings previously had no length bound and were drawn in full.
  Enforce 32 bytes, reject control characters, and bound renderer text work.
- Arbitrary Unicode in remote country names could grow the glyph cache over a long
  session. Rendering now uses a bounded printable-ASCII glyph set with replacement
  characters; receipt records still retain valid Unicode for audit purposes.
- Feed-thread creation failure previously panicked inside the macOS host. It now
  reports an offline error. Catch recoverable Rust panics at the frame/create FFI
  boundary; allocation aborts and invalid caller pointers remain outside that guard.
- Windows embedded preview no longer explicitly hides the cursor.
- Make macOS Objective-C ownership explicit and prevent preview-window close from
  automatically releasing a window still owned by the delegate.
- Repair macOS workflow bundle names and clean generated bundles instead of merging
  stale embedded resources. Verify bundle signatures from a clean extraction of the distributable ZIP.
- Lock release dependency resolution, statically link the Windows CRT, restrict CI
  permissions and pin third-party GitHub Actions to exact commits.
- Keep private project history, share links, old binaries and Git objects out of the
  publishable source export. Ignore common credential/private-key file extensions.

## Latest implementation and CI validation

Official 0.4.0 (build 8) was published on 29 October 2026 from commit
`07ec0d8ca323eb97c1165c831f8def28112aea01`. All six automated checks passed
for that commit; final public asset hashes were verified against its checksums.
These results apply to that release, not automatically to later development commits.
Windows files remain unsigned; macOS bundles are ad-hoc signed and unnotarized.

Merged PR #8 added the UTC/system-local clock, publisher-verified opt-in updater,
PowerShell 5.1/7 regression tests, macOS first-frame/lifecycle repair, and screenshot
thumbnails. All six PR checks passed before merge: quality, Windows, macOS,
updater-tests, MSI package and MSI install/uninstall. Current CI also checks
version metadata consistency. Native Mac smoke checks cover drawing before window
attachment and animation, both preview modes, restart, and thumbnail validity.
These tests do not establish real idle/lock behavior or signed N → N+1 updates.
The repaired saver was installed locally; on-device Settings preview/thumbnail
acceptance after restart remains unconfirmed.

## Checks performed locally

- Ten Rust tests pass, including invalid coordinates/schema, overlong/control
  text, oversized messages, bounded buffers/glyph cache, staleness and route expiry.
- Rust formatting and Clippy with warnings denied pass for the host workspace and
  Windows x64 code (cross-target toolchain).
- Fresh universal macOS compilation and Windows x64 release compilation/linking.
- macOS bundle signature and principal-class loading/start/stop smoke checks.
- Live release audit passed: 37,398 receipts, 102 changed payloads in 30.24 seconds.
  `evidence/live-audit.json` contains the measured snapshots. This proves changing
  deliveries, not upstream event age or unique attacks.
- Built the per-user x64 MSI and inspected its architecture, registry scope,
  shortcuts, downgrade condition and upgrade rollback sequencing. Extracted its
  cabinet and verified the SCR hash matches the fresh Windows build. No executable
  custom actions are embedded. Install/uninstall does not write screensaver/lock
  preferences; selection is a separate user-launched shortcut.
- Source pattern scan for private links, local user paths and common secrets.
  This is a limited scan, not proof that a repository contains no secrets.

## Dependency advisories

RustSec database snapshot: 40f5be6fb12ed93fc591bf4ab23b7d793b3f2239,
1,381 advisories in the recorded snapshot; the current lockfile has 310 packages.
The evidence JSON files preserve the original 0.3.0 review and its 305-package lockfile. No reported vulnerabilities found.
Four informational advisories are explicitly reviewed in `.cargo/audit.toml`:

| Advisory | Dependency | Disposition |
|---|---|---|
| RUSTSEC-2024-0429 | glib 0.18.5 | Unsound Linux GTK iterator; absent from supported Windows and macOS build graphs. |
| RUSTSEC-2024-0370 | proc-macro-error 1.0.4 | Unmaintained macro on the Linux GTK dependency branch; not used by supported builds. |
| RUSTSEC-2026-0192 | ttf-parser 0.25.1 | Unmaintained fontdue dependency; parses only the immutable bundled font, never network/user fonts. Plan migration to a maintained font stack. |
| RUSTSEC-2026-0543 | chrono 0.4.45 | Unmaintained since 2026-09-14, no reported vulnerability. Used in the core for the clock, the local UTC offset and parsing dates from feeds. Exception added 2026-11-18 so CI is not blocked; replace it (planned: jiff) in the next version. |

Both unfiltered and reviewed audit outputs are included in `evidence/`.
The CI audit fails on new, unreviewed warnings/vulnerabilities. These exceptions
must be revisited when updating dependencies or adding Linux/custom-font support.

## Hardening round for 0.8.0-rc.1

Done 15-16 November 2026 for AtlasSOC Desktop 0.8.0-rc.1 (build 15), by the coding lead (self-review; an independent
review by the documentation owner covered PR #78/#79 key handling on 15 November and found it sound for the live OTX
path, with follow-ups that were fixed or documented). Numbers are from the measured runs named below; nothing here
is a guarantee that the program is free of faults.

**Robustness of the parsers.** `crates/core/tests/osint_parsers_robustness.rs` feeds every network-facing OSINT
parser (KEV, EPSS, SANS ISC, Tor list, URLhaus JSON and CSV, ThreatFox, SSLBL, AbuseIPDB, certificate watch, OTX,
Phishing.Database, Shodan InternetDB, Spamhaus DROP and ASN-DROP, Team Cymru text, ransomware.live) with 3,000
random inputs, 6,000 mutated real-looking payloads (truncate, bit-flip, insert, repeat, NUL bytes) and eight
pathological shapes (100,000-deep nesting, a 10,000-digit number, 200,000 rows, a 2 MB line, invalid UTF-8,
100,000 NUL bytes). Deterministic seeds. Result: no panic, no hang (0.6 s in a release build).

**`unsafe` audit.** `unsafe` appears only in the C ABI used by the macOS host (`lib.rs`, `osint_ffi.rs`) and in the
Win32 host code (`windows.rs`, `soc_host.rs`, `soc_radar.rs`, `soc_config.rs`). There is none in any parser, the
network layer or the data worker. Each exported function has a documented safety contract; strings are
null-checked and UTF-8 checked, output copies are bounded by the caller's capacity, and the worker start is
wrapped in `catch_unwind`.

**Keys.** The key lives in an in-memory map in the data worker; it is not part of any page, note, cache or state
file, and is never logged. On macOS it is stored in the Keychain (service `ThreatAtlas.OSINT`), on Windows in
Credential Manager (`AtlasSOC/OSINT/...`). A source that is off, or without its key, makes no request (tested in
`nothing_is_requested_while_every_source_is_off`). Release packages are checked with
`scripts/check-test-token-absent.py`.

**Dependencies.** The CI `quality` job runs the RustSec audit with the reviewed exceptions listed above and fails
on any new advisory.

**Performance.** Frame render time (release build, 60 records per frame, Apple silicon Mac with a CI build running
at the same time): mean 11.1 ms at 1440 px width, 12.6 ms at 1920, 13.2 ms at 2560 and 14.0 ms at 3840, against a
33 ms budget. Occasional single frames took up to about 50 ms while other builds ran. Steady-state memory of the
Windows app on a partner PC: 140 MB working set (88 MB private, 344 handles, 12 threads) five minutes after start.

**Live checks on macOS with the maintainer's own keys (15 November 2026).** OTX 4 pulses; URLhaus 1,000 recent
URLs; ThreatFox 1,496 indicators in 24 hours; AbuseIPDB score 0 for the maintainer's address and 24 of 100 (28
reports, data centre) for a VPN address; certificate watch for one domain with 0 new certificates after the
baseline. Windows: ransomware.live shows 100 incidents again after the provider fixed its certificate.

**Live checks on Windows hardware (15 November 2026, partner PC, RC1 build 15 from commit 6a1dbfb).** The user's own
OTX key entered through the Credential Manager box: 4 pulses and 444 indicators. The abuse.ch key (one entry for
ThreatFox and URLhaus): ThreatFox 1,674 new indicators in 24 hours; the key was still in Credential Manager
after a restart of the app. Key removal works (zero AtlasSOC entries remained afterwards) and the sources were
switched off again. AbuseIPDB and SSLMate key entry were not repeated on Windows. The ports heading now shortens
to fit the narrow column (seen as "TOP PORTS / DSHIELD").

**CI.** All checks green on each merged pull request, including Windows x64 build, installer upgrade and
uninstall test, macOS build, Linux build, updater tests and quality (format, Clippy with warnings as errors, tests,
audit).

**Soak.** One partner Windows 11 PC (RTX 3050, 1920x1080), default sources, all other user programs closed, the 0.8.0
build 14 candidate (the RC1 build 15 differs only by the release identity, the heading stamp, in-app links and
the ports-heading fix), 74 minutes continuous (15 November 2026, 16:55:12 to 18:09:27 local, one process, no
restart): working set 140 MB after 5 minutes and 137 MB after 74 minutes, private memory 88 to 89 MB, handles 344
to 348, threads 12 to 9, CPU time 586 s in total (about 13 % of one core on average). No crash, hang or dialog.
The owner set the soak length to one hour for RC1; this is not a multi-hour soak. A second PC was assigned a
30-minute soak; it is not part of this record unless its report is added to the release record.

## Still requiring acceptance testing

- MSI installation, upgrade, rollback, user-launched setup and uninstallation on
  Windows beyond the CI lifecycle test. GitHub Actions has passed MSI installation,
  shortcut validation, preference preservation and uninstallation; signed upgrades,
  rollback failure injection and interactive user-launched setup still need acceptance.
- Latest-release interactive GUI behavior on both platforms after these changes. The owner
  confirmed the prior Windows and repaired macOS versions work. Those confirmations
  do not establish acceptance of this new release candidate.
- Actual idle activation, lock/sign-in transitions, multiple monitors, Intel Mac
  hardware, offline/resume behavior and extended memory/CPU soak testing.
- Provider authorization/terms for public distribution. Code licensing does not
  license the upstream feed. No automatic feed-freshness authenticity proof exists.
- DNS resolution is delegated to the OS and can delay background-worker shutdown.
  Network connect/read/write operations otherwise have explicit timeouts; do not
  claim immediate shutdown or zero background traffic after stopping a session.
- Developer ID/notarization and Windows Authenticode signing are not configured.
  Published 0.4.0 and development builds remain ad-hoc signed on Mac and unsigned on Windows.

Re-run these checks after dependencies or implementation change. Keep prior
known-working releases available until the candidate passes platform acceptance.
