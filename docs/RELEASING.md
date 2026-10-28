# Versions and releases

`version.json` is the authoritative release manifest. The current development
preview is 0.4.0-rc.1, build 7; this does not mean that downloads are published.

- `version`: numeric major.minor.patch shared by Rust, macOS and MSI. It must fit
  MSI limits (255.255.65535). Increase it for every new public installer version.
- `build`: monotonically increasing positive integer for macOS CFBundleVersion.
- `prerelease`: `rc.N` for a preview, or JSON `null` for a stable release. The tag
  is derived as `v<version>-rc.N` or `v<version>`.

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
5. Upload matching Windows MSI, macOS ZIP, source archive and SHA-256 checksums.
   Include the source commit, product version, Mac build, signing/notarization
   status and known acceptance limits in the notes. Verify the public links.

The updater accepts stable releases only. Its macOS asset name stays
`ThreatAtlas-macOS.zip`; Windows uses `ThreatAtlas-<version>-x64.msi`. Source and
Windows ZIP names include the derived tag. See UPDATES.md for signature/key rules.
Do not overwrite old release assets with new payloads under an old tag/version.
Keep previous downloads available and publish a new preview when the checks pass.
