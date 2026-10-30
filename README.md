# Release status protocol

This status-only branch deliberately contains no application code or Actions workflows. Do not merge it into main or release branches.

Robert approves in Ibert Consulting Telegram. MAC records the verified decision, source reference and time in status/mac.json. GitHub status never invents owner approval.

Ownership: @IbertMACBot alone edits status/mac.json (dashboard decision, approvals, tasks and independently verified evidence). @IbertAgentControlBot alone edits status/billy.json (his reported handoff/progress/evidence). Reported tests are not independent validation. Include updated_at (ISO8601), updated_by, exact source commit/version/build, evidence links/hashes, limits and next action. Never publish credentials, private group transcripts, tokens, private paths or live telemetry. Publish concise project status only.

Writes are change-driven, not heartbeat commits. Fetch current file SHA, compare semantic content excluding updated_at, skip unchanged writes, then update with that SHA. On conflict refetch/reconcile; never force-push or overwrite the other file. At least one second between mutations. No CI build for status updates.

One dashboard process polls sequentially every ten minutes on UTC minute 00/10/20/30/40/50. Clients refresh only the local server. Billy should avoid independent polling; if needed, check no more often than ten minutes at05/15/25/35/45/55. Slots do not grant additional quota. Use stable URLs, If-None-Match with saved ETags, persistent caches, x-poll-interval and reset/Retry-After headers. Back off on403/429, exponentially on secondary limits; stop repeated permanent4xx errors. Unauthenticated304 requests still consume quota. Never use extra credentials to evade limits. No public webhook listener is required on the Mac.

Dashboard retains last successful source with a visible stale/error indicator. Last updated means content change, not read time. Telegram remains for owner approvals, urgent questions and brief handoff notices; routine status uses these files.
