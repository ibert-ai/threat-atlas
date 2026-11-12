#!/usr/bin/env bash
# AtlasSOC Desktop for Linux (preview): relocatable AppDir and .tar.gz in dist.
# Separate from scripts/build-linux.sh so the screensaver's publish job never picks this package up.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $(uname -s) != Linux ]]; then
  echo 'Build the AtlasSOC Linux preview on Linux.' >&2
  exit 1
fi
cargo build --release --locked -p threat-atlas-linux --bin atlassoc
version=$(python3 -I -c "import json; print(json.load(open('atlassoc-beta-version.json'))['version'])")
build=$(python3 -I -c "import json; print(json.load(open('atlassoc-beta-version.json'))['build'])")
arch=$(uname -m)
name="AtlasSOC-Linux-${arch}-v${version}-build${build}-preview"
appdir="dist/AtlasSOC-Linux-${arch}.AppDir"
rm -rf "$appdir"
mkdir -p "$appdir/usr/bin" "$appdir/usr/share/doc/atlassoc"
cp target/release/atlassoc "$appdir/usr/bin/"
cp linux/atlassoc.desktop "$appdir/"
cp assets/atlassoc/sentinel/sentinel.svg "$appdir/atlassoc.svg"
cp LICENSE PRIVACY.md THIRD-PARTY-NOTICES.txt assets/FONT-LICENSE.txt assets/ATTRIBUTION.md docs/ATLAS-SOC-LINUX.md "$appdir/usr/share/doc/atlassoc/"
cat > "$appdir/AppRun" <<'RUN'
#!/bin/sh
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$HERE/usr/bin/atlassoc" "$@"
RUN
chmod +x "$appdir/AppRun"
python3 -I - "$appdir" "$version" "$build" "$arch" <<'PY'
import hashlib, json, subprocess, sys
appdir, version, build, arch = sys.argv[1:5]
git = lambda *a: subprocess.run(['git', *a], capture_output=True, text=True).stdout.strip()
binary = open(appdir + '/usr/bin/atlassoc', 'rb').read()
json.dump({
    'product': 'AtlasSOC', 'publisher': 'Ibert Consulting', 'version': version, 'build': int(build),
    'platform': 'linux-' + arch, 'source_commit': git('rev-parse', 'HEAD'),
    'source_dirty': bool(git('status', '--porcelain', '--untracked-files=no')),
    'signature': 'unsigned',
    'package': 'windowed preview for X11/XWayland; not a screensaver or lock screen',
    'radar_network': 'none; Cloudflare Radar is not included in the Linux preview',
    'sha256': hashlib.sha256(binary).hexdigest(),
}, open(appdir + '/manifest.json', 'w'), indent=2)
PY
# The CL Cloudflare Radar TEST token must never ship: exit 1 rejects, exit 2 means no token to compare.
token_check=0
python3 -I scripts/check-test-token-absent.py "$appdir" || token_check=$?
if [[ $token_check -eq 1 ]]; then echo 'Build rejected: test token found' >&2; exit 1; fi
tar -C dist -czf "dist/${name}.tar.gz" "$(basename "$appdir")"
echo "dist/${name}.tar.gz"
