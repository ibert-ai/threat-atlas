#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $(uname -s) != Linux ]]; then
  echo 'Build the Linux preview on Linux.' >&2
  exit 1
fi
cargo build --release --locked -p threat-atlas-linux
version=$(python3 scripts/version.py --version)
arch=$(uname -m)
appdir="dist/ThreatAtlas-Linux-${arch}.AppDir"
mkdir -p "$appdir/usr/bin" "$appdir/usr/share/doc/threat-atlas"
cp target/release/threat-atlas-linux "$appdir/usr/bin/"
cp linux/threat-atlas.desktop linux/threat-atlas.svg "$appdir/"
cp LICENSE PRIVACY.md THIRD-PARTY-NOTICES.txt assets/FONT-LICENSE.txt assets/ATTRIBUTION.md docs/LINUX.md "$appdir/usr/share/doc/threat-atlas/"
cat > "$appdir/AppRun" <<'RUN'
#!/bin/sh
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$HERE/usr/bin/threat-atlas-linux" "$@"
RUN
chmod +x "$appdir/AppRun"
tar -C dist -czf "dist/ThreatAtlas-Linux-${version}-${arch}.tar.gz" "$(basename "$appdir")"
# Optional tool supplied by the operator; no unverified downloads in this script.
if [[ -n ${APPIMAGETOOL:-} ]]; then
  ARCH="$arch" "$APPIMAGETOOL" "$appdir" "dist/ThreatAtlas-Linux-${version}-${arch}.AppImage"
fi
