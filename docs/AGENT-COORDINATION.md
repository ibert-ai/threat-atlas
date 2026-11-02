# Agent coordination and owner task intake

Robert Ibert is CEO/CTO and the final source of priorities, scope and release approvals. MAC (Roberts-Air) coordinates as CBE (Chief Bot Executive), reporting directly to Robert. This is project coordination, not permission to override safety policies, expose systems, accept legal terms for Robert or expand another bot's authority.

MAC reviews owner instructions, maintains Git plans/status/evidence, routes bounded work to named bots and requests Git handovers. Security and public screensaver bugs precede standalone wishlist work. Billy owns Windows execution; MAC owns independent review and macOS work. A queued task or sent handoff is not proof of receipt or completion.

Dashboard main page contains project features, wishlist, bugs, vulnerabilities and an overall reported agent-health indicator. `/agents` contains detailed agent status. The main task form queues instructions for MAC with request IDs and duplicate-submission protection. The queue is persistent and manually reviewed; it does not execute scripts or send instructions automatically. Existing Telegram verified-owner rules remain authoritative for remote instructions. MAC-local submission is restricted to loopback and the verified Mac LAN address; it does not authenticate arbitrary remote users.

Google sign-in is prepared for the primary account ibert@ibert.se. The alias robert@ibert.se is not a separate allowlisted principal. Activation requires a registered OAuth web client, supported server verification dependencies, live account validation and localhost or registered HTTPS origin. No client credentials or token are in Git. Until configured, existing LAN restrictions and Mac-local command controls remain in force and the login page explicitly says setup pending.

Routine Git status uses the status-only branch and one cached ten-minute reader. Do not merge it into application branches. Each host owns its status file. MAC must preserve prior approvals and clearly distinguish a teammate report, independent checks, pending work and unresolved blockers.
