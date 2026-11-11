# Versions and releases

`version.json` is the authoritative release manifest. The official unsigned
release is 0.4.0, build 8. Stable status does not imply trusted signatures.
The current manifest is the stable 0.4.8 release, build 16, for Windows x64, the
Linux preview and macOS. It is published only after exact-source automated checks
and package validation, and replaces 0.4.5 as latest stable. Historical assets remain unchanged.

The maintainer authorized unsigned publication on 29 October 2026. For 0.4.0,
the signing and manual acceptance gates below remain incomplete and must be
disclosed in release notes. All six automated checks must pass for the exact
published commit. Keep updater signature enforcement unchanged.

- `version`: numeric major.minor.patch shared by Rust, macOS and MSI. It must fit
  MSI limits (255.255.65535). Increase it for every new public installer version.
- `build`: monotonically increasing positive integer for macOS CFBundleVersion.
- `prerelease`: `beta.N` or `rc.N` for a preview, or JSON `null` for a stable
  release. The tag is derived as `v<version>-<prerelease>` or `v<version>`.

After editing the manifest, run `python3 scripts/version.py --write`, then
`python3 scripts/version.py --check`. Commit the manifest and generated Cargo,
lockfile, macOS and MSI metadata together. Workspace crates inherit the shared
Cargo version. Build/packaging scripts read the manifest; CI rejects stale metadata.
Update the release status and changelog at the same time. Re-running the sync is
idempotent. Historical release/evidence versions must remain unchanged.

A prerelease suffix is not supported by MSI ProductVersion. Do not ship several
public MSIs with different payloads under the same numeric version: changing only
`rc.N` or the Mac build number will not create a newer Windows upgrade. Advance the
numeric version as well when publishing another installer payload. The first
signed 1.0.0 installer will use a newer numeric version than these previews.

## Publish checklist

1. Update manifest, sync metadata, changelog and release notes on a PR.
2. Pass all required CI checks and perform platform acceptance, including the
   actual Mac Settings preview, idle/lock behavior and signed upgrade tests.
3. Build from the exact reviewed commit; sign and verify final artifacts as
   described in SIGNING.md. Keep signing credentials out of PR builds.
4. Create the derived tag and a GitHub release for that same commit. Mark it as
   a prerelease whenever `prerelease` is non-null. Never relabel a preview as a
   stable update or claim signing approval before it exists.
5. Upload matching Windows MSI, macOS ZIP, Linux preview archive, source archive and SHA-256 checksums.
   Include the source commit, product version, Mac build, signing/notarization
   status and known acceptance limits in the notes. Verify the public links.

The updater accepts stable releases only. Its macOS asset name stays
`ThreatAtlas-macOS.zip`; Windows uses `ThreatAtlas-<version>-x64.msi`. Source and
Windows ZIP names include the derived tag. See UPDATES.md for signature/key rules.
Do not overwrite old release assets with new payloads under an old tag/version.
Keep previous downloads available and publish a new preview when the checks pass.

The current manual publication job is restricted to v0.4.8 and creates the
Windows + Linux stable release as latest. AtlasSOC releases share this repository:
always create them with `--latest=false`, because the screensaver updaters read
`releases/latest`. Preparing or merging
the version does not authorize publication. Review its exact tag guard, release
notes, prerelease flag and acceptance evidence before manually dispatching it.

## Known bugs in every release

Include a **Known bugs** section for the exact release version and platforms.
List confirmed defects, affected versions, issue links and workarounds; identify
unverified reports and incomplete acceptance separately. Update
[KNOWN-BUGS.md](KNOWN-BUGS.md) when a fix is verified and name its first released
version. Do not describe a candidate fix as available in an older download.

## OS-by-OS beta publication —4 November2026
Robert directs each OS to ship its next beta after applicable checks pass,without waiting for another OS. A release may initially contain only one platform. List included/excluded assets and exact commit/version/test limits explicitly. Add a platform only from the same tagged source with matching metadata and accepted evidence;otherwise use a new version/tag rather than changing source of an existing release. Preserve historical binaries and signing/update restrictions. Old manual workflow remains guarded for0.4.2 and must not be used for this new release;MAC handles reviewed platform-specific publication.

## Stable decision — 4 November 2026

Robert authorizes Windows/Linux stable0.4.5/build13 from the approved0.4.4RC implementation after final exact-source checks. The numeric version advances for new MSI payload identity;prerelease=null. macOS is excluded while Gatekeeper trust is unresolved. Unsigned publication and disclosed manual/hardware test limits remain explicitly accepted;stable status does not manufacture missing results or weaken updater signing enforcement. The earlier prerelease-only checklist applies to previews;this scoped owner decision authorizes this stable publication.

## Stable decision — 11 November 2026

Robert (owner) orders the stable release now instead of Friday 13 November: screensaver 0.4.8/build 16 and AtlasSOC Desktop 0.7.0/build 13, built from main after the Seeker theme merge (not selectable in release builds). The screensaver's numeric version advances from 0.4.7-rc.1 for MSI payload identity; prerelease=null for both. Windows stays unsigned; macOS packages are Developer ID signed and notarized. Disclosed hardware/manual test limits remain accepted and are listed in the release notes; stable status does not manufacture missing results.
