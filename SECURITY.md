# Security policy

Threat Atlas is a visual telemetry viewer, not security protection software.
Report suspected vulnerabilities privately using GitHub's **Report a vulnerability**
feature when enabled by the repository owner. Do not publish exploit details in a
public issue before the maintainer can respond. Only the latest release is maintained.

The app connects to GreyNoise's public threat-map service over certificate-validated
TLS. The service receives the user's IP address and normal connection metadata.
No login, credentials or cookies are used. There is no updater, arbitrary URL input,
network scanning, execution of incoming data, or opening of observed IP addresses.

Live records are untrusted input. Payloads, strings, history and drawing work are
bounded. Only the bundled font and map are parsed as assets. The app does not
verify upstream event authenticity, event age or uniqueness: counters are receipts.
The provider's availability and schema are outside this project's control.

See docs/QUALITY.md for checks and explicit dependency-review exceptions.
A clean audit and code signature do not guarantee absence of bugs or malware.
