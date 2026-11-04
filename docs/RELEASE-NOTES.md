# Threat Atlas screensaver 0.4.4-rc.1 candidate — Windows MSI and Linux preview

Product 0.4.4, build 12. Candidate only until platform assets are published. Publish each OS separately after its applicable exact-source checks; no waiting for another OS. Previous tags and packages remain unchanged. No macOS package is planned here while downloaded installation remains blocked by Gatekeeper.

## Windows

The corrected all-users MSI installs one x64 SCR into System32, documents into Program Files and three Start Menu items. Approve its administrator prompt after checking source and checksum. Manual System32 copying requires **Run as administrator**. Do not routinely run the saver elevated. Uninstall the old per-user installation first: the MSI refuses to overlap it. The all-users MSI omits automatic updates; use verified manual packages pending updater redesign.

Earlier candidate 773a1062d2704508a9384e603b5bb6d9f3fcb35c passed hosted package/lifecycle checks. Native candidate testing reported successful real per-user refusal, installed layout and uninstall; the owner confirmed Settings listing, small/full preview and one-minute idle start. This is prior-candidate evidence, not fresh 0.4.4 package acceptance. Lock-on-resume, browser download/Zone.Identifier, post-uninstall Settings state and between-version upgrade remain untested. Windows edition/build details in the reported environment need reconciliation. Unsigned publisher warnings remain.

## Linux

Earlier v0.4.2-rc.1 exact source 684a63bd4c21428d126f04aa4d3156bdcea232c9 retests report three bounded source Xvfb smoke passes, measured resize and held-Escape exit. Owner manual GNOME XWayland resize and Escape passed. Reviewed recovery logs show LIVE to STALE to OFFLINE to LIVE with increasing records. The earlier timeout was not reproduced; cause remains unconfirmed. Instant synthetic Escape may be missed because input is polled per frame. These results do not establish fresh 0.4.4 acceptance.

Linux remains a windowed X11/XWayland preview, without idle/lock integration. Physical GPU, multimonitor and broader desktop acceptance remain untested. Final source/package hashes and exact-source CI evidence must accompany publication. No synthetic threats or TLS bypasses.
