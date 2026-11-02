#!/bin/sh
set -eu
cd "$(dirname "$0")"
OUT="${ATLAS_BETA_OUTPUT:-/private/tmp/ThreatAtlas-Radar-PrivateBeta}"
mkdir -p "$OUT/Threat Atlas Radar Private Beta.app/Contents/MacOS"
APP="$OUT/Threat Atlas Radar Private Beta.app"
# The map is drawn by the shared screensaver core (crates/core). Universal by default (Apple silicon
# and Intel); ATLAS_BETA_ARCHS="arm64" builds one slice. SwiftUI APIs used here need macOS 14.
command -v cargo >/dev/null 2>&1 || PATH="$HOME/.cargo/bin:$PATH"
export MACOSX_DEPLOYMENT_TARGET=14.0
set --
for arch in ${ATLAS_BETA_ARCHS:-arm64 x86_64}; do
  case "$arch" in
    arm64) target=aarch64-apple-darwin ;;
    x86_64) target=x86_64-apple-darwin ;;
    *) echo "Unknown architecture: $arch" >&2; exit 1 ;;
  esac
  cargo build --locked --release -p threat-atlas-core --target "$target" --manifest-path ../../Cargo.toml
  CORE="${CARGO_TARGET_DIR:-../../target}/$target/release/libthreat_atlas_core.a"
  xcrun swiftc -target "$arch-apple-macos14" -module-cache-path "$OUT/module-cache-$arch" -parse-as-library \
    -import-objc-header RadarCoreFFI.h RadarCore.swift RadarModel.swift CoreAtlasView.swift RadarApp.swift "$CORE" \
    -o "$OUT/AtlasRadar-$arch" \
    -framework SwiftUI -framework Security -framework CoreFoundation -framework SystemConfiguration -liconv
  set -- "$@" "$OUT/AtlasRadar-$arch"
done
lipo -create "$@" -output "$APP/Contents/MacOS/AtlasRadar"
rm -f "$@"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>dev.threatatlas.private.radar</string><key>CFBundleName</key><string>Threat Atlas Radar Private Beta</string><key>CFBundleExecutable</key><string>AtlasRadar</string><key>CFBundleShortVersionString</key><string>0.5.0</string><key>CFBundleVersion</key><string>6</string><key>LSMinimumSystemVersion</key><string>14.0</string><key>NSHighResolutionCapable</key><true/></dict></plist>
PLIST
codesign --force --sign - "$APP"
printf '%s\n' "$APP"
