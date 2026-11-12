# AtlasSOC Desktop for Linux — preview

A first Linux build of AtlasSOC Desktop: the same SOC view, feed, renderer and TLS validation as the Windows and macOS apps, in a resizable window. x86_64, X11 or XWayland. It is a preview: it is not a screensaver, not a lock screen, and it changes no system settings.

## Run

Extract the archive and start `AppRun` in the extracted folder (or `usr/bin/atlassoc`). `AppRun --help` prints the controls.

| Key | Action |
|---|---|
| R / C / S | Realtime / Calm / Still animation |
| L | Classic / Dashboard layout |
| 1 / 2 / 3 | Show or hide malicious / suspicious / benign |
| Space | Freeze or resume the display (the feed continues) |
| F1 or H | Print the help in the terminal |
| Esc | Quit |

Left-click a country to focus it; click it again to clear. Hovering a country shows its counts in the window title. Make the window wider (up to 2.4:1) to get the Top countries column.

## Not included in the preview

- Cloudflare Radar. No token is read and nothing is requested from Cloudflare, so there is no licence prompt.
- Update check, saved settings, a fullscreen toggle, menus and a table view.
- Native Wayland, `.deb`/`.rpm` packages and an AppImage.

## Data and privacy

GreyNoise public threat-map records over `wss://threat-map-api.greynoise.io/ws` with TLS validation. They are received records, not verified unique attacks. No analytics, no probing of observed hosts.

## Test status and limits

Built and started by CI on Ubuntu 24.04 under a virtual display (Xvfb): the offline smoke test presents three frames, including the wide layout, without constructing a feed. Not tested: a physical Linux desktop, live feed delivery on Linux, other distributions, HiDPI scaling, GPU drivers, multiple monitors, long runs. The binary needs the glibc and X11 libraries of Ubuntu 24.04 or newer. Unsigned.

## Build from source

```sh
sudo apt-get install build-essential pkg-config libx11-dev libxext-dev libxrandr-dev libxcursor-dev libxi-dev
bash scripts/build-linux-soc.sh
```
