# Privacy policy

Threat Atlas SOC displays public GreyNoise internet threat-map telemetry.
When the screensaver or preview runs, it automatically connects to
`wss://threat-map-api.greynoise.io/ws`. GreyNoise receives your public IP address
and normal connection metadata, such as connection time. DNS requests are handled
by your configured DNS resolver. GreyNoise controls the upstream service; see
https://www.greynoise.io/privacy-policy for its privacy practices.

The application does not require an account, cookies or API keys. It adds no
analytics, advertising or tracking. Received telemetry is kept in bounded memory
for display and is discarded when the process ends. It does not visit, probe or
connect to observed IP addresses. OS crash reports are subject to your OS settings.

The optional developer audit tool writes received country/coordinate records,
receipt times, counters, payload fingerprints and rendered frames to a local
folder you choose. It does not upload those audit files.

GitHub handles repository downloads, issues and discussions under GitHub's own
privacy policy. Signing providers process release artifacts and maintainer account
information under their own policies. This policy does not claim that third-party
services collect no data. Changes to network behavior should update this policy.

If you enable automatic updates, a separate per-user background task checks the
public GitHub releases API at login/daily (macOS) or daily while signed in
(Windows). It downloads stable updates from GitHub and its release-asset CDN over
HTTPS, verifies publisher code signatures locally, and installs them. GitHub/CDN
operators receive your IP address and normal request metadata. No account/token
is sent. A local status file records the latest result; it is not uploaded.
Disable updates from the preview app menu (macOS) or Start Menu (Windows).

## AtlasSOC standalone beta

The standalone beta first requires version/build/terms consent before constructing its GreyNoise worker. On Windows and macOS, a user-supplied Radar Read token, kept in Windows Credential Manager or macOS Keychain, lets the app retrieve past-day aggregates from api.cloudflare.com after consent, at most every 15 minutes, until paused or the token is removed. It retains aggregate cache/receipt time and persisted cooldown under Application Support/ThreatAtlasPrivateRadar with one worker lock and a15-minute request floor. Data is aggregated, not individual live events. No added analytics or host probing. Profile/Keychain data is not deleted automatically on bundle/folder removal. The standalone installs no updater/startup task; screensaver updater statements above apply only to that separate product. See docs/ATLAS-SOC-BETA.md for all paths, scope and limitations.
