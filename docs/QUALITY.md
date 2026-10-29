# Quality and security review — 28 October 2026

Original review: 0.3.0; updated for the 0.4.0 preview development line. This is a source review and automated checks,
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
Three informational advisories are explicitly reviewed in `.cargo/audit.toml`:

| Advisory | Dependency | Disposition |
|---|---|---|
| RUSTSEC-2024-0429 | glib 0.18.5 | Unsound Linux GTK iterator; absent from supported Windows and macOS build graphs. |
| RUSTSEC-2024-0370 | proc-macro-error 1.0.4 | Unmaintained macro on the Linux GTK dependency branch; not used by supported builds. |
| RUSTSEC-2026-0192 | ttf-parser 0.25.1 | Unmaintained fontdue dependency; parses only the immutable bundled font, never network/user fonts. Plan migration to a maintained font stack. |

Both unfiltered and reviewed audit outputs are included in `evidence/`.
The CI audit fails on new, unreviewed warnings/vulnerabilities. These exceptions
must be revisited when updating dependencies or adding Linux/custom-font support.

## Still requiring acceptance testing

- MSI installation, upgrade, rollback, user-launched setup and uninstallation on
  Windows beyond the CI lifecycle test. GitHub Actions has passed MSI installation,
  shortcut validation, preference preservation and uninstallation; signed upgrades,
  rollback failure injection and interactive user-launched setup still need acceptance.
- Latest-preview interactive GUI behavior on both platforms after these changes. The owner
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
  The release candidate remains ad-hoc signed on Mac and unsigned on Windows.

Re-run these checks after dependencies or implementation change. Keep prior
known-working releases available until the candidate passes platform acceptance.
