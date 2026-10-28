#!/bin/bash
set -euo pipefail
export MACOSX_DEPLOYMENT_TARGET=12.0
cd "$(dirname "$0")/.."
stage=$(mktemp -d "${TMPDIR:-/tmp}/threatatlas-build.XXXXXX")
source_dir="$PWD"
trap 'rm -rf "$stage"' EXIT
cp -R Cargo.toml Cargo.lock LICENSE PRIVACY.md THIRD-PARTY-NOTICES.txt .cargo crates assets macos "$stage/"
cd "$stage"
# Build for the current architecture, or pass --universal for both architectures.
if [[ "${1:-}" == "--universal" ]]; then
  rustup target add aarch64-apple-darwin x86_64-apple-darwin
  targets=(aarch64-apple-darwin x86_64-apple-darwin)
else
  case "$(uname -m)" in arm64) targets=(aarch64-apple-darwin);; x86_64) targets=(x86_64-apple-darwin);; *) exit 1;; esac
fi
mkdir -p dist/ThreatAtlasSOC.saver/Contents/MacOS
cp macos/Info.plist dist/ThreatAtlasSOC.saver/Contents/
sign_identity="${MACOS_SIGN_IDENTITY:--}"
sign_options=(--force --sign "$sign_identity")
if [[ "$sign_identity" != "-" ]]; then
  sign_options+=(--options runtime --timestamp)
fi
binaries=()
updaters=()
for target in "${targets[@]}"; do
  cargo build --locked --release -p threat-atlas-core --target "$target"
  case "$target" in aarch64*) arch=arm64;; *) arch=x86_64;; esac
  clang -arch "$arch" -mmacosx-version-min=12.0 -fobjc-arc -bundle \
    macos/ThreatAtlasView.m "${CARGO_TARGET_DIR:-target}/$target/release/libthreat_atlas_core.a" \
    -framework ScreenSaver -framework Cocoa -framework CoreGraphics -framework CoreFoundation -framework Security \
    -framework SystemConfiguration -liconv -o "dist/ThreatAtlas-$arch"
  binaries+=("dist/ThreatAtlas-$arch")
  swiftc -target "$arch-apple-macos12" macos/Updater.swift -o "dist/Updater-$arch"
  updaters+=("dist/Updater-$arch")
done
if [[ ${#binaries[@]} == 1 ]]; then
  cp "${binaries[0]}" dist/ThreatAtlasSOC.saver/Contents/MacOS/ThreatAtlas
else
  lipo -create "${binaries[@]}" -output dist/ThreatAtlasSOC.saver/Contents/MacOS/ThreatAtlas
fi
xattr -cr dist/ThreatAtlasSOC.saver
codesign "${sign_options[@]}" dist/ThreatAtlasSOC.saver
codesign --verify --strict dist/ThreatAtlasSOC.saver
mkdir -p "dist/Threat Atlas SOC.app/Contents/MacOS" "dist/Threat Atlas SOC.app/Contents/Resources"
cat > "dist/Threat Atlas SOC.app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.threatatlas.preview.v4</string>
<key>CFBundleName</key><string>Threat Atlas SOC</string>
<key>CFBundleExecutable</key><string>ThreatAtlasPreview</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.3.0</string>
<key>LSMinimumSystemVersion</key><string>12.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
lipo -create "${updaters[@]}" -output "dist/Threat Atlas SOC.app/Contents/MacOS/ThreatAtlasUpdater"
codesign "${sign_options[@]}" "dist/Threat Atlas SOC.app/Contents/MacOS/ThreatAtlasUpdater"
clang -arch arm64 -arch x86_64 -mmacosx-version-min=12.0 -fobjc-arc macos/Preview.m -framework Cocoa -framework ScreenSaver -o "dist/Threat Atlas SOC.app/Contents/MacOS/ThreatAtlasPreview"
ditto dist/ThreatAtlasSOC.saver "dist/Threat Atlas SOC.app/Contents/Resources/ThreatAtlasSOC.saver"
cp LICENSE PRIVACY.md THIRD-PARTY-NOTICES.txt assets/FONT-LICENSE.txt assets/ATTRIBUTION.md "dist/Threat Atlas SOC.app/Contents/Resources/"
xattr -cr "dist/Threat Atlas SOC.app"
codesign "${sign_options[@]}" "dist/Threat Atlas SOC.app"
codesign --verify --strict "dist/Threat Atlas SOC.app"
mkdir -p "$source_dir/dist"
# Replace generated bundles instead of merging: a merge leaves stale resources
# behind, invalidating the signature when embedded bundle names change.
for bundle in "ThreatAtlasSOC.saver" "Threat Atlas SOC.app"; do
  rm -rf -- "$source_dir/dist/$bundle"
  ditto --noextattr --norsrc "dist/$bundle" "$source_dir/dist/$bundle"
done
# Verify the distributable from a clean temporary directory. Cloud file providers
# may attach Finder metadata to loose bundles in the destination at any time.
python3 - "$source_dir/dist/ThreatAtlas-macOS.zip" <<'ZIP'
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import sys
with ZipFile(sys.argv[1], 'w', ZIP_DEFLATED) as archive:
    for name in ['ThreatAtlasSOC.saver', 'Threat Atlas SOC.app']:
        for path in (Path('dist')/name).rglob('*'):
            if path.is_file(): archive.write(path, path.relative_to('dist'))
ZIP
mkdir -p verify
ditto --noextattr --norsrc -xk "$source_dir/dist/ThreatAtlas-macOS.zip" verify
codesign --verify --strict verify/ThreatAtlasSOC.saver
codesign --verify --strict "verify/Threat Atlas SOC.app"
printf 'Built and verified %s/dist/ThreatAtlas-macOS.zip\n' "$source_dir"
