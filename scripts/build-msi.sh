#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
test -f dist/ThreatAtlas.scr || { echo 'Build the Windows SCR first.' >&2; exit 1; }
"${WIXL:-wixl}" -a x64 -o dist/ThreatAtlas-0.3.0-x64.msi installer/ThreatAtlas.wxs
