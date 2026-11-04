# Windows installation and troubleshooting

Applies to the unsigned 0.4.5 stable installer; Windows 10/11 x64 only. Windows 10/11 x64 only.

**Windows MSI temporarily withdrawn:** the current beta's MSI download is unavailable while installation-path/integration behavior is investigated. The SCR executable is not established to be defective. The standalone Windows ZIP remains available for manual evaluation. Do not treat the MSI steps below as a currently available download; they document the corrected all-users installer, published as 0.4.5 after exact-version checks. The withdrawn 0.4.2-rc.1 MSI was per-user and installed under `%LOCALAPPDATA%\ThreatAtlas`.

## All-users MSI installation

1. Download the MSI from the [published release](https://github.com/ibert-ai/threat-atlas/releases). Check its SHA-256 against that release's checksum manifest.
2. Install the MSI and approve the administrator prompt. It installs one 64-bit `ThreatAtlas.scr` into `%WINDIR%\System32` and its documents into `%ProgramFiles%\Threat Atlas`. If an older per-user install exists, the installer stops: uninstall that one first.
3. Open **Start > Threat Atlas SOC > Set up Threat Atlas**, then select the saver, choose the wait time and Apply.
4. **Preview Threat Atlas** opens a normal live window. A working windowed preview does not prove Settings discovery or idle activation.

If the saver is absent from Screen Saver Settings, do not assume installation is complete merely because the MSI finished. Check that `%WINDIR%\System32\ThreatAtlas.scr` exists, note the Windows build and package version, and report the setup shortcut's result. Hosted installation tests cover files, shortcuts, preference preservation and uninstall; interactive Settings discovery must also be tested.

## Downloaded files and Windows' Unblock option

The MSI/SCR are unsigned. A matching checksum establishes agreement with the published download; it does not establish trusted publisher signing.

Windows may attach an Internet-zone marker to a download or extracted file. After reviewing the source and choosing to trust the particular file, inspect **right-click > Properties > General**. If an **Unblock** checkbox is present, select it and Apply for that file. This is a deliberate user action; the installer should not silently remove markers.

For the standalone Windows ZIP, you may unblock the trusted ZIP before extracting, or inspect the extracted `ThreatAtlas.scr` individually afterward. A working folder such as `C:\Temp\ThreatAtlas` is convenient, but changing folders is not proof that the Internet-zone marker has been removed. Recheck the actual extracted file.

Do not disable SmartScreen, Defender or organizational policy, and do not recursively unblock a whole Downloads folder. If policy blocks execution or Unblock is unavailable, use the administrator-approved installation route.

Microsoft documents the [Unblock operation and source-review requirement](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/unblock-file).

## System-wide directory and architecture considerations

On 64-bit Windows, `%WINDIR%\System32` is the native 64-bit system directory; `%WINDIR%\SysWOW64` is the 32-bit system directory. 32-bit processes may see redirected paths. See Microsoft's [file-system redirector guidance](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector).

This release supplies an x64 SCR. The MSI installs it to `System32` only, and its uninstall removes that copy. Do not copy the same file into `SysWOW64`. For manual System32 copying, open the copying tool or terminal with **Run as administrator**. The MSI requests elevation itself; routine screensaver execution does not need elevation. System-directory writes require administrator access, and manually copied files are not owned or removed by the MSI. Avoid stale duplicate copies when evaluating upgrades or uninstalling.

The MSI and SCR are unsigned, so the administrator prompt shows an unknown publisher. Check the checksum before approving it.

## Uninstall and reporting

Select another screen saver first, then uninstall through **Windows Settings > Apps**. Preserve the user's password, sign-in, idle and lock preferences. Record any manually deployed copies separately; do not delete unrelated Windows files.

For a bug report, include exact product/build and Windows version, MSI versus ZIP, download/extraction method, whether Unblock was available, the setup result and redacted screenshots. A next-release fix requires real Settings selection/preview/idle validation as well as MSI upgrade/uninstall checks.

## Updates

The all-users MSI does not include the per-user automatic updater. It cannot safely replace a per-machine installation. Until a reviewed redesign exists, install future verified packages manually.
