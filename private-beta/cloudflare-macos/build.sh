#!/bin/sh
set -eu
cd "$(dirname "$0")"
OUT="${ATLAS_BETA_OUTPUT:-/private/tmp/ThreatAtlas-Radar-PrivateBeta}"
mkdir -p "$OUT/Threat Atlas Radar Private Beta.app/Contents/MacOS"
APP="$OUT/Threat Atlas Radar Private Beta.app"
# The map is drawn by the shared screensaver core (crates/core), built for this Mac's architecture.
command -v cargo >/dev/null 2>&1 || PATH="$HOME/.cargo/bin:$PATH"
cargo build --locked --release -p threat-atlas-core --manifest-path ../../Cargo.toml
CORE="${CARGO_TARGET_DIR:-../../target}/release/libthreat_atlas_core.a"
xcrun swiftc -module-cache-path "$OUT/module-cache" -parse-as-library -import-objc-header RadarCoreFFI.h \
  RadarCore.swift RadarModel.swift CoreAtlasView.swift RadarApp.swift "$CORE" -o "$APP/Contents/MacOS/AtlasRadar" \
  -framework SwiftUI -framework Security -framework CoreFoundation -framework SystemConfiguration -liconv
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>dev.threatatlas.private.radar</string><key>CFBundleName</key><string>Threat Atlas Radar Private Beta</string><key>CFBundleExecutable</key><string>AtlasRadar</string><key>CFBundleShortVersionString</key><string>0.3.0</string><key>CFBundleVersion</key><string>3</string><key>NSHighResolutionCapable</key><true/></dict></plist>
PLIST
codesign --force --sign - "$APP"
printf '%s\n' "$APP"
