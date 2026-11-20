# Threat Atlas — agent rules

Applies to every agent (CL, MAC/MacGyver, Seek, Billy and future agents). Robert retains all owner decisions. Private project rules in the local checkout still apply; this file adds the public-safe handover rule.

## Handover
A handover is complete only when every step below is done. A comment, a chat message, a mention or a Telegram notice is not a handover.

- **Owner is a field, not a sentence.** Set the receiving agent as Owner on the board item and as assignee on the issue. Writing "MAC owns this" in a comment does not change ownership.
- **One handover, one issue.** Each handover is its own issue (or a dedicated handover record in the private `handovers/` files), never a reply buried in another thread. It contains:
  - what is handed over and why, and what the receiver is asked to do (review, implement, approve layout, etc.);
  - every file with exact path, branch/commit and **SHA-256**;
  - **acceptance criteria** the receiver can check one by one;
  - known limits, blockers and what is explicitly out of scope.
- **Receiver acknowledges in the issue.** The receiver writes an acknowledgement in that issue naming the exact reference (issue number, commit, SHA-256) and either starts or states a blocker. Until that acknowledgement exists, the sender reports the item as *offered*, not *handed over*, and keeps following up.
- **Keep states separate.** Offered, acknowledged, in progress, reviewed/accepted and published are different states. Never report a later state than the evidence shows.
- **Summary for Robert.** Robert reads only what is shown to him; he does not scan files. Every handover and every acknowledgement includes a summary of at most three lines, posted where Robert reads (the issue body or comment he is notified about): what it is, who owns it now, what Robert must decide (or "nothing"), and one link. He must be able to answer yes or no from that summary alone.
- **Publishing always needs Robert's explicit approval.** An agent's review or approval (for example MAC signing off a layout) is not permission to publish, release, merge to `main` or post publicly. Ask Robert and record his answer in the issue before publishing.
- **If you are unsure who owns something, ask in the issue** and leave the Owner field unchanged rather than claiming or assigning it from a comment.
