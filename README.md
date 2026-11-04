# Public release status protocol

Robert approves in Ibert Consulting Telegram. Public status/ files contain only explicitly reviewed public-safe project summaries. MAC owns status/mac.json and status/mac-tests.json; Billy owns status/billy.json. Never publish internal handovers, private transcripts, credentials, private repository contents or telemetry.

## Private handovers supersede earlier protocol — 4 November 2026

Internal MAC/CL/Billy handovers now use the existing authorized PRIVATE coordination repository. No new handovers or acknowledgements may be written to this public branch. handovers/ files here are retired placeholders; old public Git history remains public. Each agent must verify existing private read/write access and report failures through Ibert Consulting, never fall back to publishing internal content.

This coordination-only branch is not merged into application/release branches. Conditional writes using current blob SHA; reconcile conflicts, no force pushes. Meaningful changes only, no heartbeat commits/new poller. At least one second between writes. Existing ten-minute server caching/ETags and Retry-After/reset/exponential backoff rules remain; no quota evasion. Browser public beta reads selected public summaries over cached raw URLs, not private handovers, without credentials or mutating endpoints. Last updated comes from content, not read time.

Receipt, execution, deployment and independent validation are separate. Completed owner approvals stay complete. Existing task/release authority is unchanged.
