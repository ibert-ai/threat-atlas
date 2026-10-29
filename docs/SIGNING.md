# Release signing

## Current project status

Official 0.4.0 was published without trusted signing. Windows artifacts are
unsigned; macOS bundles are ad-hoc signed and not notarized. Stable release
status does not mean a verified publisher signature. Certificate acquisition
and signing work are on hold. Keep updater signature verification enabled;
unsigned releases cannot establish trusted automatic updating.

Let's Encrypt issues TLS certificates, not code-signing certificates:
https://letsencrypt.org/docs/faq/

## Windows
Use a publicly trusted Authenticode identity with a hardware/cloud protected key.
For an eligible open-source project, apply to https://signpath.org/ (acceptance is
required; the service holds the signing key). A certificate alone is not the whole
cost: token/cloud storage and signing subscriptions may be additional charges.
Azure Artifact Signing currently accepts EU organizations but individual applicants
only in the US/Canada. Check eligibility before buying anything.

Certificate-store/token workflow on Windows:
1. Build SCR with scripts/build-windows.ps1.
2. Sign dist/ThreatAtlas.scr with scripts/sign-windows.ps1 -Thumbprint YOUR_THUMBPRINT -File dist/ThreatAtlas.scr.
3. Build MSI using scripts/build-msi.sh on Linux/macOS with msitools/wixl.
4. Sign the versioned MSI in dist/ (name from scripts/version.py --msi-name) on Windows with the same script.
5. Verify both signatures and test the final MSI on a fresh Windows account.
For a cloud service such as SignPath/Azure, insert the provider's signing step at
steps 2 and 4. Azure needs its client tools/dlib and account metadata; the generic
certificate-store script alone does not implement Azure signing.

For GitHub Actions, use a protected release environment and short-lived federated
credentials where supported. Never give pull-request builds signing access.
Timestamp every signature. Signing does not promise immediate SmartScreen reputation.
A self-signed certificate is useful for a controlled lab; it is not publicly trusted.
Do not ask users to disable Windows security protections to install a release.

## macOS
An Apple Developer Program account and Developer ID Application certificate with
its private key are needed to sign the app and screensaver. A Developer ID Installer
certificate is additionally needed if distributing a signed PKG installer.

Set MACOS_SIGN_IDENTITY to the Developer ID Application identity when running
scripts/build-macos.sh --universal. Without it the script uses local ad-hoc signing.
For public release submit a ZIP containing the signed bundles with:

    xcrun notarytool submit release.zip --keychain-profile YOUR_PROFILE --wait

Use a previously configured local Keychain profile or a securely stored App Store
Connect API key. Never commit key files, passwords or exported P12 certificates.
Review the notarization log, validate the final archive, and test it with Gatekeeper
on a clean Mac. ZIP files cannot themselves be stapled; distribute a supported
stapled app/DMG/PKG as appropriate. Test screensaver-host loading as well as the app.

References:
- https://developer.apple.com/help/account/certificates/create-developer-id-certificates/
- https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution
- https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart
