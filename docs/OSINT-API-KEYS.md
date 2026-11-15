# AtlasSOC Desktop beta API keys and tester steps

This guide applies to beta builds that expose the corresponding source in OSINT settings. Record the platform, version and build before testing. If a control is absent, record it as unavailable in that build. See [OSINT sources](OSINT-SOURCES.md) for provider terms, attribution and refresh intervals.

Use your own provider credentials. Enter them only in the app's settings for that source. Keep them out of screenshots, logs, issue reports and Git. Start with the source disabled, save your key if the build supports it, then enable the source and try the action below. Restart and verify the configured state persists. Disable the source and remove its key after testing. Record successful retrieval, a provider error or an unavailable control without including the key.

## abuse-ch

Use your abuse.ch Auth-Key for ThreatFox and URLhaus. Enable the source you want to test and check that its list updates. SSLBL uses its public feed and needs no key.

## alienvault-otx

Use your AlienVault OTX API key. Enable OTX and check that the app can retrieve public subscribed pulses. An empty subscription or no eligible pulses can produce an empty view.

## abuseipdb

Use your AbuseIPDB API key. Run one explicit lookup for a public IP you are authorized to submit. Verify the confirmation and check the returned report summary. The provider receives the submitted address. A cached result may be reused.

## sslmate-cert-spotter

Use your SSLMate Cert Spotter API key. Add a domain you are authorized to monitor and check the issuance view after a refresh. The provider receives the watched domain. An empty result can mean there are no new issuances.

## Windows installer acceptance

1. Verify the package checksum against the checksum supplied with the exact build and record Windows version, package version and install scope.
2. Run the installer on the authorized test machine. Record whether UAC appears and whether it matches the chosen install scope. Record any SmartScreen prompt or Defender detection, including the exact wording.
3. If device policy blocks installation, stop and record the block. Keep SmartScreen and Defender enabled.
4. If installation is permitted, launch AtlasSOC, verify its displayed version, open the OSINT settings and test the relevant sources. For an upgrade, check that previously saved preferences survive. Record what was actually exercised.

## macOS first-open acceptance

1. Verify the package checksum and record macOS version, architecture and package version.
2. Open the app from Finder and record any first-open approval prompt. Use the normal approval flow only where the device's policy permits it. If macOS blocks launch, record the exact message.
3. After launch, verify the displayed version and exercise only the source controls available on that build. Record any Keychain prompt and whether a saved configuration survives restart.
