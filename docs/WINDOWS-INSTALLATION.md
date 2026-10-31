# Windows installation and troubleshooting

Applies to the unsigned 0.4.2-rc.1 beta. Windows 10/11 x64 only.

## Per-user MSI installation

1. Download the MSI from the [published release](https://github.com/ibert-ai/threat-atlas/releases/tag/v0.4.2-rc.1). Check its SHA-256 against that release's checksum manifest.
2. Install the MSI. Its intended location is `%LOCALAPPDATA%\ThreatAtlas`; it does not install the saver into Windows system directories.
3. Open **Start > Threat Atlas SOC > Set up Threat Atlas**, then select the saver, choose the wait time and Apply.
4. **Preview Threat Atlas** opens a normal live window. A working windowed preview does not prove Settings discovery or idle activation.

If the saver is absent from Screen Saver Settings, do not assume installation is complete merely because the MSI finished. Check that `%LOCALAPPDATA%\ThreatAtlas\ThreatAtlas.scr` exists, note the Windows build and package version, and report the setup shortcut's result. Hosted installation tests cover files, shortcuts, preference preservation and uninstall; interactive Settings discovery must also be tested.

## Downloaded files and Windows' Unblock option

The MSI/SCR are unsigned. A matching checksum establishes agreement with the published download; it does not establish trusted publisher signing.

Windows may attach an Internet-zone marker to a download or extracted file. After reviewing the source and choosing to trust the particular file, inspect **right-click > Properties > General**. If an **Unblock** checkbox is present, select it and Apply for that file. This is a deliberate user action; the installer should not silently remove markers.

For the standalone Windows ZIP, you may unblock the trusted ZIP before extracting, or inspect the extracted `ThreatAtlas.scr` individually afterward. A working folder such as `C:\Temp\ThreatAtlas` is convenient, but changing folders is not proof that the Internet-zone marker has been removed. Recheck the actual extracted file.

Do not disable SmartScreen, Defender or organizational policy, and do not recursively unblock a whole Downloads folder. If policy blocks execution or Unblock is unavailable, use the administrator-approved installation route.

Microsoft documents the [Unblock operation and source-review requirement](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/unblock-file).

## System-wide directory and architecture considerations

On 64-bit Windows, `%WINDIR%\System32` is the native 64-bit system directory; `%WINDIR%\SysWOW64` is the 32-bit system directory. 32-bit processes may see redirected paths. See Microsoft's [file-system redirector guidance](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector).

This release supplies an x64 SCR. Treat copying that same file into both directories as a deployment scenario requiring validation, not a universal installation requirement. System-directory writes require administrator access and manually copied files are not owned or removed by this per-user MSI. Avoid stale duplicate copies when evaluating upgrades or uninstalling.

A future system-wide installer option must explicitly handle elevation, architecture, correct file ownership and cleanup. The current beta does not supply that option.

## Uninstall and reporting

Select another screen saver first, then uninstall through **Windows Settings > Apps**. Preserve the user's password, sign-in, idle and lock preferences. Record any manually deployed copies separately; do not delete unrelated Windows files.

For a bug report, include exact product/build and Windows version, MSI versus ZIP, download/extraction method, whether Unblock was available, the setup result and redacted screenshots. A next-release fix requires real Settings selection/preview/idle validation as well as MSI upgrade/uninstall checks.
