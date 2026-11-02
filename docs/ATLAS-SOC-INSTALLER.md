# AtlasSOC final-version Windows installer requirements

Owner: Robert. Recorded 2 November 2026. Status: required for the final standalone release; specification only, not implemented or tested. This does not reopen Billy's current test assignment or authorize replacing his work.

## Installation scope and location

The installer must offer **Just me** and **Everyone using this computer** before installation begins.

| Scope | Executable location | Privileges | Visibility |
| --- | --- | --- | --- |
| Everyone | `%ProgramFiles%\AtlasSOC\AtlasSOC.exe`, normally `C:\Program Files\AtlasSOC\AtlasSOC.exe` for a native 64-bit build | Elevation for install/repair/update/removal | All users |
| Just me | `%LocalAppData%\Programs\AtlasSOC\AtlasSOC.exe` | Standard user; no machine-wide writes | Installing user only |

Resolve Windows known folders or installer directory properties. Do not hardcode drive C, an account name or a translated Program Files directory. The owner-requested all-users directory name is exactly **AtlasSOC**. The executable name **AtlasSOC.exe** is the proposed final product name, to be reconciled with final release metadata.

Proposed default: Just me. Always show the resolved destination and scope in the confirmation screen. Cancelling elevation must cancel the all-users operation cleanly; never silently change scope. The installed application runs unelevated.

## Shortcut choices

Ask independently, using visible checkboxes:

- **Add a desktop shortcut** — proposed default off.
- **Add a Start menu shortcut** — proposed default on.

Both choices must be available in either scope. All-users shortcuts use the public desktop and common Start menu Programs known folders. Per-user shortcuts use the installing user's desktop and Start menu Programs known folders, including redirected desktop locations. Do not automatically pin to Start or the taskbar, add a startup task, or associate file types.

Shortcut display name: **AtlasSOC**. Start menu group, if used: **AtlasSOC**. Publisher: **Ibert Consulting**. The shortcuts, application EXE, installer and Installed apps entry use the approved product icon; use an embedded resource or a durable installed icon path, never a temporary download path. A publisher label is not evidence of a digital signing certificate.

Remember scope and shortcut choices for update/repair. Respect intentionally absent shortcuts; an upgrade must not silently recreate them. Make later shortcut changes an explicit installer/maintenance action. Scope migration must be explicit, preserve per-user data and avoid duplicate registrations.

## Data, consent and lifecycle

Keep writable settings/cache/logs in each user's profile even for an all-users installation. Never write runtime data into Program Files. Credentials remain in the platform credential store per user. Each user accepts the applicable data terms for the exact release/build/terms; one administrator's install or acceptance cannot accept on behalf of all users. Never accept terms automatically through an unattended install.

Register version, publisher, icon and uninstall operation in the correct per-user or per-machine Installed apps context. Uninstall only this product's files/shortcuts/registrations. Preserve personal data/credentials unless removal is explicitly chosen. Keep the existing screensaver and known-working releases separate.

## Acceptance evidence required before final release

Test both scopes with a standard account and administrator account; all four combinations of the two shortcut checkboxes; paths containing spaces/non-ASCII characters; redirected desktop and non-default system drive where feasible; cancellation/elevation failure; launch as a different standard user after an all-users install; no cross-user settings/token/consent leakage; repair, update, scope-conflict handling and uninstall. Record exact source/package version, hash, Windows version, account context, results and limits. Verify icon appearance in Explorer, title bar, taskbar, Alt-Tab, Start, desktop and Installed apps at 100%, 150% and 200% scaling in light/dark themes.

Windows Installer supports per-machine/per-user contexts and folder/shortcut redirection: [Installation context](https://learn.microsoft.com/en-us/windows/win32/msi/installation-context), [Single-package authoring](https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/Msi/single-package-authoring.md). A bootstrapper may expose these choices, but its implementation must preserve the same semantics.
