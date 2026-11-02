# Atlas status dashboard sections

`sections.html` adds individual feature, wishlist, bug, dependency-currency and Known Vulnerabilities sections to the existing LAN monitor. Data comes from the monitor's cached `/api/project-status` response (MAC-owned `status/mac.json` on the status-only branch). One backend reader polls Git every ten minutes; browser refreshes use cached local data. Keep existing host/subnet restrictions and Mac-local command mutation policy.

Known Vulnerabilities are sorted by numeric CVSS base score descending, unknown scores last. Display the source vector, affected component, individual resolution status and advisory links. Empty/unavailable evidence is not a clean result. CVSS is owned by FIRST and used by permission; see https://www.first.org/cvss/v3.1/specification-document . Security score describes advisory severity, not proven local exploitability.

Never merge the status branch into application code. The service preserves its SQLite database and runs as a per-user LaunchAgent from Application Support; a running dashboard is not agent health. Hosting remains restricted to the previously authorized LAN and loopback. Historical reported evidence stays separate from independently verified checks.
