# Known Vulnerabilities

No current clean-scan claim is made until a fresh audit of the exact source and lockfile finishes. This section tracks confirmed findings, not an assurance that none exist. Application security review is separate from dependency advisory scanning.

| Score | Advisory / source | Affected component | Status | Fix / validation |
|---|---|---|---|---|
| Not yet verified | [RustSec advisory database](https://rustsec.org/advisories/) | Current Cargo.lock | Fresh audit pending | Build gate fails closed until verified. |

Display numeric CVSS scores highest first; unknown scores last. Never invent a score from a severity label. Preserve resolved findings with the exact first fixed version and verification date; distinguish package presence from exploitability on a given platform. Privately disclose unpublished code vulnerabilities under [SECURITY.md](../SECURITY.md).
