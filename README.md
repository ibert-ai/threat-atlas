# Release status protocol

This status-only branch deliberately contains no application code or Actions workflows. Do not merge it into main or release branches.

Robert approves in Ibert Consulting Telegram. MAC records the verified decision, source reference and time in status/mac.json. GitHub status never invents owner approval.

Ownership: @IbertMACBot alone edits status/mac.json (dashboard decision, approvals, tasks and independently verified evidence). @IbertAgentControlBot alone edits status/billy.json (his reported handoff/progress/evidence). Reported tests are not independent validation. Include updated_at (ISO8601), updated_by, exact source commit/version/build, evidence links/hashes, limits and next action. Never publish credentials, private group transcripts, tokens, private paths or live telemetry. Publish concise project status only.

Writes are change-driven, not heartbeat commits. Fetch current file SHA, compare semantic content excluding updated_at, skip unchanged writes, then update with that SHA. On conflict refetch/reconcile; never force-push or overwrite the other file. At least one second between mutations. No CI build for status updates.

One dashboard process polls sequentially every ten minutes on UTC minute 00/10/20/30/40/50. Clients refresh only the local server. Billy should avoid independent polling; if needed, check no more often than ten minutes at05/15/25/35/45/55. Slots do not grant additional quota. Use stable URLs, If-None-Match with saved ETags, persistent caches, x-poll-interval and reset/Retry-After headers. Back off on403/429, exponentially on secondary limits; stop repeated permanent4xx errors. Unauthenticated304 requests still consume quota. Never use extra credentials to evade limits. No public webhook listener is required on the Mac.

Dashboard retains last successful source with a visible stale/error indicator. Last updated means content change, not read time. Telegram remains for owner approvals, urgent questions and brief handoff notices; routine status uses these files.

## CL status handoff and Docker dashboard verification

CL reports meaningful implementation/test changes to MAC in Ibert Consulting using the existing dedicated connector. Do not add a receiver or schedule. Include a unique reference, UTC timestamp, owner, exact branch/commit, product version/build, concise change, each check with PASS/FAIL/NOT RUN and evidence location/hash, limitations/blockers and next action. Distinguish reported results from independent validation; delivery/queue acknowledgement is not execution. No credentials, private transcripts or live telemetry.

CL does not overwrite status/mac.json or status/billy.json. MAC reconciles the CL handoff and updates status/mac.json with its current blob SHA; Billy updates status/billy.json. Owner decisions remain complete. Change-driven updates only; preserve deduplication checkpoints and content timestamps. No repeated unchanged reports or duplicate GitHub polling.

MAC also updates the relevant saved data/status.json in private ibert-ai/project-status-dashboard, then sends Billy its exact commit. This is a separate repository and deployment step: updating this public status branch alone does not update a Docker container's mounted local snapshot. Billy fetches the exact dashboard revision, preserves persistent data/secrets/access controls and rollback, updates the mounted snapshot as appropriate, and safely recreates/restarts only if required. He reports deployed source/image, data revision/hash and health results.

Verification: CL explicitly acknowledges the protocol reference and supplies one structured meaningful handoff when available. MAC verifies the source/evidence before labelling it verified. After Billy deploys the data revision, MAC checks /healthz, /api/status and rendered page over LAN; compare the intended content revision/hash and saved updated_at, not page refresh time. Record mismatch as stale deployment and coordinate correction; do not treat HTTP200 as data freshness. Receipt, deployment and independent validation are separate states.

Release handoff: Billy supplies exact Windows candidate/source/version, package/checksums and native/installer/consent results with limits. MAC performs a light, risk-based independent final review, reusing applicable exact-source evidence; rerun focused checks for new deltas or unresolved failures. Complete final versioned installation/privacy/licensing/known-issue/release notes and download/checksum records before authorized publication. Publish only after applicable gates pass; otherwise coordinate the concrete blocker. No duplicate platform implementation or blanket re-testing while Billy is executing assigned checks.
