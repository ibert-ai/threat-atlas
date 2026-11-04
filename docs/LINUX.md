# Linux application preview (development)

This branch adds a native windowed Linux host using the same Rust feed, renderer,
TLS validation, and stale/offline behaviour as Windows and macOS. It does **not**
register an idle screensaver, replace a lock screen, or change security settings.
The initial target is x86_64 Linux with X11/XWayland. Native Wayland and specific
Ubuntu/Red Hat-family distribution support require real-device validation.

## Build and run

Install stable Rust, a C compiler, pkg-config and X11 development libraries.
For Ubuntu CI: `sudo apt-get install build-essential pkg-config libx11-dev libxext-dev libxrandr-dev libxcursor-dev libxi-dev xvfb`.

```sh
cargo build --release --locked -p threat-atlas-linux
./target/release/threat-atlas-linux
```

Escape or close exits; the window can be resized. Rendering is limited to 30 fps.
`--smoke-test` opens a window, presents three frames and exits; it does not prove
live-feed delivery or real desktop compatibility. It can run under Xvfb in CI.

## Distribution

`bash scripts/build-linux.sh` creates a relocatable AppDir and `.tar.gz` in dist.
Extract the archive and launch its `AppRun`. The same source is a candidate for
Ubuntu and Red Hat-family systems, but compiled binaries have a minimum glibc and
system-library baseline. This archive is not guaranteed to run on every Linux.
Build on the oldest supported baseline and test on each selected distribution.

Set `APPIMAGETOOL` to an installed, independently verified appimagetool executable
to also create an AppImage. The script does not download or execute an unverified
packaging tool, and does not claim to bundle every shared library. Inspect the
binary dependencies and validate the AppImage on clean target systems before
publishing. Native `.deb`/`.rpm` packages and desktop screensaver integration are
follow-up work. Linux packages are development candidates until platform checks
and review pass; existing Windows/macOS releases are unchanged.

## Desktop test baseline and rollback checkpoint

Use the latest generally available stable Ubuntu Desktop x86_64 release as the
primary acceptance-test OS. Resolve it from Canonical at the start of each test
cycle and record the exact release/point version, kernel, official media hash,
verification time and source URL. Daily, development, beta and release-candidate
Ubuntu images do not qualify. Older supported distributions are separately named
compatibility cases; they do not substitute for the primary latest-stable run.
This OS policy does not silently replace the explicitly assigned Atlas candidate.

Install Ubuntu onto the VM's persistent disk, detach installation media and verify
the guest root filesystem is disk-backed rather than a live ISO/overlay. Refresh
official package indexes, finish required upgrades, check package-manager health,
complete any required reboot and verify the resulting update/kernel state.

Before installing Atlas or project build prerequisites and before any Atlas test,
shut the clean updated guest down and take/verify the rollback checkpoint
`01-Clean-Ubuntu-Updated-Before-Atlas`. Preserve it. A snapshot of an empty disk,
a live ISO session or a partially updated system does not satisfy this gate.
Unknown or failed evidence blocks the test run; VM Running alone is insufficient.

The structured checklist, required evidence and package-versus-source test cases
are in [LINUX-TEST-SCHEMA.json](LINUX-TEST-SCHEMA.json). Packaging may still use the
oldest supported build baseline for ABI portability; acceptance testing and build
baseline selection are separate decisions. VM results do not establish physical
hardware, idle/lock integration, GPU or multi-monitor acceptance.
