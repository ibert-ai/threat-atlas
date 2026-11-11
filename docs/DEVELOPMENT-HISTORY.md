# Development history

11 November 2026 — Owner reports CL is building screensaver 0.4.8. Updated the
README, changelog, release preparation, release process and known-limit references
to distinguish active work from published 0.4.7 history. Documentation baseline:
78315c426b8eef5e263ec4b0cb87155a89419910. No source, package metadata, workflow,
release asset or historical test evidence changed. Final build and acceptance
evidence remain pending; see [0.4.8 preparation](RELEASE-0.4.8.md).

29 October 2026 — country-map / Linux development branch:
- Added cached country borders and expiring classification shading, sharing feed
  colours and preserving polygon holes/islands. Conflict rule: highest active
  category; both reported endpoints included.
- Added a Linux windowed host, relocatable archive/AppDir packaging, optional
  operator-supplied AppImage tooling, and planned Linux CI smoke validation.
- Existing v0.4.0 release artifacts are untouched. No wishlist item is marked
  complete. Windows validation by the second agent and user visual approval are
  required before push/release; Linux native screensaver support is not claimed.
