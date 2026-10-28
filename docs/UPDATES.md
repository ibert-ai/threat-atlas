# Automatic updates

The next signed release includes optional per-user updates. Existing unsigned
0.3 previews need one final manual install of that signed release to establish
publisher trust and install the updater. No release has been signed by this change.

## Behavior

Windows installs the updater with the MSI. Start Menu shortcuts enable, disable,
or check updates. Enabling registers a limited, interactive-user Scheduled Task
at noon daily, with missed runs caught up when the user next signs in. No password,
elevation or execution-policy bypass is used. Managed execution policies may
require signing the PowerShell script as well as the SCR and MSI.

macOS includes a compiled universal Swift helper inside the signed preview app.
Its menu enables/disables a LaunchAgent. Enable requires a Developer ID signed app
and an already installed, matching signed saver in `~/Library/Screen Savers`.
The app is copied to `~/Applications` if needed. Launchd checks at login/load and
every 24 hours. System-wide screen saver installations are not auto-updated.

Both use the fixed public `ibert-ai/threat-atlas` GitHub latest-stable-release API,
HTTPS, strict three-part versions, and reject prereleases/downgrades. Failed
checks leave the current installation in place. Windows defers when ThreatAtlas
runs; macOS also defers for screen saver hosts, System Settings and the preview.
An update may therefore wait for a later daily check. No lock/idle/password
preferences are changed and no process is forcibly terminated. macOS uses staged
bundle replacement and rollback on an installation error; Windows uses MSI
transaction rollback. A Mac update takes effect on the next saver launch.

## Release contract and trust

- Publish stable tags `vMAJOR.MINOR.PATCH` only after quality and installer checks.
- Windows asset: `ThreatAtlas-MAJOR.MINOR.PATCH-x64.msi`. Sign SCR and MSI using
  the same trusted signing key; timestamp signatures. The updater requires valid
  Authenticode signatures and pins the installed SCR's signing public key.
  A changed signing key requires a manual trusted upgrade, even when the publisher
  name stays the same. Update MSI ProductVersion and DocsVersion every release;
  keep the UpgradeCode and per-user installation path.
- Mac asset: `ThreatAtlas-macOS.zip`, containing `ThreatAtlasSOC.saver` and
  `Threat Atlas SOC.app` with the embedded updater. Both bundle versions must
  match the release tag. Sign nested components before the app using a Developer
  ID Application identity; notarize and staple the app before packaging. The
  updater checks Apple Developer ID signatures, exact bundle identifiers and the
  installed Team ID, plus Gatekeeper assessment of the candidate app. Keep these
  identifiers stable. A Team ID change requires a manual trusted upgrade.
- GitHub API metadata/checksums alone never authorize installation. Unsigned,
  ad-hoc-signed, wrong-publisher or rejected artifacts fail closed. Never disable
  these checks to ship a preview. CI artifacts are not update sources.

## Status and removal

Windows: `%LOCALAPPDATA%\ThreatAtlas\update-status.txt`. Use **Disable automatic
updates** before uninstalling. If omitted, the orphaned task removes itself at
its next run when it finds the saver absent.

macOS: `~/Library/Logs/ThreatAtlas-update.log`. Disable in the preview menu before
removing the app/saver. Manual removal: unload
`~/Library/LaunchAgents/dev.threatatlas.updater.plist` with `launchctl bootout`,
then delete that plist. Disabling does not remove the installed app or saver.

## Required release validation

In addition to compile/parser/version tests, test a signed N → N+1 upgrade on a
clean Windows user and Intel/Apple Silicon Mac. Verify enabled/disabled scheduling,
existing saver selection and password settings, active saver deferral, offline
retry, unchanged-version no-op, rejected unsigned/wrong-signer/older/prerelease
artifacts, interrupted download, failed install rollback, and uninstall cleanup.
These end-to-end signed tests require signing credentials and two signed versions;
unsigned CI does not demonstrate that automatic installation works end to end.
