# Cloudflare Radar test token

Robert (owner), 9 November 2026: CL may use a dedicated Cloudflare Radar test/demo token for
development tests. Shipping versions must never contain it.

## Rules

- **Scope:** custom Cloudflare API token with one permission, Account · Radar · Read, and a
  short expiry (30 days). Robert creates, rotates and revokes it in the Cloudflare dashboard.
- **Storage:** only in the testing Mac's Keychain, service `IbertConsulting.CL.CloudflareRadarTest`,
  account `radar-read-test`. Robert types the value into Keychain himself. It is separate from the
  app's own user token item (`ThreatAtlas.PrivateRadarBeta` / `RadarRead`).
- **Use:** test code reads it from Keychain at run time inside the test process. Never print it,
  put it in command arguments, environment files, logs, screenshots, Git, chat or handovers.
- **Never shipped:** no build reads this Keychain item. Shipping builds use each user's own token,
  entered in the app and stored in that user's Keychain (customer steps:
  [CLOUDFLARE-RADAR-TOKEN-GUIDE.md](CLOUDFLARE-RADAR-TOKEN-GUIDE.md)).

## Leak check

`python3 -I scripts/check-test-token-absent.py PATH ...` reads the test token from Keychain and
fails if its bytes appear anywhere under the given paths (plain, UTF-16LE, base64 and inside ZIP
members). It prints only file names and PASS/FAIL. Exit codes: 0 absent, 1 found, 2 token not on
this machine (skipped).

- The macOS build (`private-beta/cloudflare-macos/build.sh`) runs it on the finished app and
  rejects the build on a hit.
- Before any package is published, run it on the exact package (Windows ZIP/MSI, macOS app) on the
  machine that holds the token. CI has no Keychain, so CI runs report SKIP, not PASS.
