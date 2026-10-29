#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/version.py --check
msi_name=$(python3 scripts/version.py --msi-name)
test -f dist/ThreatAtlas.scr || { echo 'Build the Windows SCR first.' >&2; exit 1; }
"${WIXL:-wixl}" -a x64 -o "dist/$msi_name" installer/ThreatAtlas.wxs
