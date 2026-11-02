# AtlasSOC working identity — Sentinel

Current owner instruction: use Sentinel for the local standalone SOC now and share the assets/instructions with the other implementation agents. All four original concepts remain preserved locally; the final design decision is still open. This is a working identity, not release approval.

## Instructions for implementation agents

- **CL / macOS:** use the exact checked-in `assets/atlassoc/sentinel/AtlasSOC.icns` in the standalone app's `Contents/Resources` and set `CFBundleIconFile` to `AtlasSOC.icns` before signing. Add the resource through the build, not by patching a previously signed release. Re-sign only newly built development artifacts. Verify both app architectures, bundle resource/hash and signature, then Finder/Dock appearance at the next coordinated launch. Do not start another telemetry worker to check an icon.
- **Billy / Windows:** embed `assets/atlassoc/sentinel/AtlasSOC.ico` in the standalone EXE and use the same product mark for installer, desktop/Start shortcuts and Installed apps. Check title bar/taskbar/Alt-Tab, Explorer, shortcut and uninstall icon identity at relevant DPI/theme settings. Use the installer scope/shortcut rules in [ATLAS-SOC-INSTALLER.md](ATLAS-SOC-INSTALLER.md). Coordinate adoption with current checks; if source/package changes, identify and revalidate the resulting exact candidate rather than reusing old test evidence.
- **MAC:** owns asset consistency, independent validation, integration and final release documentation. Other agents may use these task-scoped assets on their assigned review branches without repeat permission. Report exact source/version/package hashes and limits in Ibert Consulting. No merge/tag/release/publication authority is granted by this document.
- **Linux, if separately assigned:** derive hicolor PNG sizes 16/24/32/48/64/128/256/512 and scalable SVG from the same master; name the desktop icon consistently. This asset guidance does not assign or authorize a Linux port.

This document governs product identity and the installer presentation only. It does not replace the SOC map/dashboard layout or weaken existing release, telemetry, TLS, consent, credential or platform-scope rules. Preserve the screensaver and existing releases. No public package is to be patched in place.

## Visual layout

Use the shield outline, cyan observation pulse and amber endpoint as one mark. Preserve the SVG geometry, palette, aspect ratio and transparent outer margin. Do not add a padlock, text, health badge, animated alert, or simulated telemetry to the icon. The cyan and amber are fixed identity colours, not live health/severity values.

Product label: **AtlasSOC**. Publisher text: **Ibert Consulting**. In installer/About/docs, place the product mark to the left of the product name, with `by Ibert Consulting` as secondary text. In compact desktop/taskbar/Dock surfaces, use the mark alone. Do not shrink the full publisher name into a small icon. The publisher text is not a claim of certificate signing. Corporate logo artwork is not part of this asset set.

Navy: `#0A1828` and `#17334A`. Foreground: `#EAF4F8`. Cyan: `#40DBDC`. Amber: `#F1B76B`. Prefer restrained surfaces, clear spacing and system typography. Use a native single-colour template/symbolic variant for status-bar contexts where needed; the supplied monochrome SVG is a starting master and needs optical validation.

## Asset provenance and verification

Original editable artwork created for this project. `sentinel.svg` is the colour master; `sentinel-mono.svg` is its monochrome counterpart. `sentinel-1024.png`, `AtlasSOC.ico` and `AtlasSOC.icns` are draft exports of that master. `manifest.json` records SHA256 hashes. ICO has 15 sizes:16,20,24,30,32,36,40,48,60,64,72,80,96,128,256. ICNS was produced from the ten Apple iconset slots (16/32/128/256/512 points at1x/2x). Local export structure/dimensions and iconutil conversion passed. The current local Mac development bundle's matching icon/resource and strict ad-hoc signature were checked; native Windows/Linux shell acceptance remains pending. Draft asset acceptance must not be represented as release acceptance.

## Reference guidance

- [Microsoft icon construction](https://learn.microsoft.com/en-us/windows/apps/design/iconography/app-icon-construction)
- [Apple iconset slots](https://developer.apple.com/library/archive/documentation/Xcode/Reference/xcode_ref-Asset_Catalog_Format/IconSetType.html)
- [Freedesktop icon theme specification](https://specifications.freedesktop.org/icon-theme/)
