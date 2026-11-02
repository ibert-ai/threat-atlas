# Known Vulnerabilities

Fresh RustSec audit on 2 November 2026 of source `f695e86` and its unchanged Cargo.lock found zero known advisory findings and no audit warnings. This does not establish absence of application vulnerabilities. This section tracks confirmed findings, not an assurance that none exist. Application security review is separate from dependency advisory scanning.

| Score | Advisory / source | Affected component | Status | Fix / validation |
|---|---|---|---|---|
| — | [RustSec advisory database](https://rustsec.org/advisories/) | Audited Cargo.lock | No known advisory findings in this scan | Source/lockfile details in `evidence/security/latest.json`. |

Display numeric CVSS scores highest first; unknown scores last. Never invent a score from a severity label. Preserve resolved findings with the exact first fixed version and verification date; distinguish package presence from exploitability on a given platform. Privately disclose unpublished code vulnerabilities under [SECURITY.md](../SECURITY.md).

## Dependency maintenance findings (not confirmed vulnerabilities)

Current-build gate is blocked pending review/testing of newer `sha2` 0.11.1 (locked 0.10.9), `tiny-skia` 0.12.0 (locked 0.11.4), `tungstenite` 0.30.0 (locked 0.29.0), and older `windows-sys` versions remaining alongside 0.61.2 in the dependency tree. Sources: https://crates.io/crates/sha2 · https://crates.io/crates/tiny-skia · https://crates.io/crates/tungstenite · https://crates.io/crates/windows-sys . No vulnerability score is assigned to version currency alone. These are not verified fixes; do not release while the security gate is blocked.
