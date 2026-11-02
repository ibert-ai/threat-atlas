#!/bin/sh
set -eu
cd "$(dirname "$0")"
OUT="${ATLAS_BETA_OUTPUT:-/private/tmp/ThreatAtlas-Radar-PrivateBeta}"
mkdir -p "$OUT/Threat Atlas Radar Private Beta.app/Contents/MacOS"
APP="$OUT/Threat Atlas Radar Private Beta.app"
mkdir -p "$APP/Contents/Resources"
# Read-only copy of the shared Natural Earth land map for the private atlas prototype.
cp ../../assets/land.json "$APP/Contents/Resources/land.json"
xcrun swiftc -module-cache-path "$OUT/module-cache" -parse-as-library RadarCore.swift RadarModel.swift RadarAtlasCore.swift RadarAtlasView.swift RadarApp.swift -o "$APP/Contents/MacOS/AtlasRadar" -framework SwiftUI -framework Security
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>dev.threatatlas.private.radar</string><key>CFBundleName</key><string>Threat Atlas Radar Private Beta</string><key>CFBundleExecutable</key><string>AtlasRadar</string><key>CFBundleShortVersionString</key><string>0.1.0</string><key>CFBundleVersion</key><string>1</string><key>NSHighResolutionCapable</key><true/></dict></plist>
PLIST
codesign --force --sign - "$APP"
printf '%s\n' "$APP"
