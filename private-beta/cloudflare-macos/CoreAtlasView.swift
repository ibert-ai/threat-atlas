import SwiftUI
import CoreGraphics

// Standalone SOC map drawn by the shared Rust core (crates/core, ta_radar_*): the same renderer, map,
// country outlines and font as the screensaver. This file only hands snapshots in and shows frames.

/// Rebuilds a provider-shaped body from the parsed snapshot so the core applies its own validation.
func coreBody(_ result: RadarResult) -> Data? {
    struct Body: Encodable { let success = true; let result: RadarResult }
    return try? JSONEncoder().encode(Body(result: result))
}

final class CoreAtlas {
    private let session = ta_radar_new()
    private var handed: Date?          // receipt time of the snapshot last given to the core
    private(set) var accepted = true   // false when the core rejected that snapshot
    deinit { ta_radar_drop(session) }

    /// Gives a new snapshot to the core once, then renders the current frame (clock, freshness).
    func frame(result: RadarResult?, received: Date?) -> CGImage? {
        guard let session else { return nil }
        if let result, let received, received != handed {
            handed = received
            let ms = UInt64(max(0, received.timeIntervalSince1970 * 1000))
            accepted = coreBody(result).map { body in
                body.withUnsafeBytes { raw in
                    ta_radar_set(session, raw.bindMemory(to: UInt8.self).baseAddress, raw.count, ms) == 0
                }
            } ?? false
        }
        guard let pixels = ta_radar_frame(session) else { return nil }
        let width = Int(ta_width()), height = Int(ta_height())
        // Copy now: the core reuses its buffer on the next frame.
        guard let provider = CGDataProvider(data: Data(bytes: pixels, count: width * height * 4) as CFData)
        else { return nil }
        return CGImage(width: width, height: height, bitsPerComponent: 8, bitsPerPixel: 32,
                       bytesPerRow: width * 4, space: CGColorSpaceCreateDeviceRGB(),
                       bitmapInfo: CGBitmapInfo(rawValue: CGImageAlphaInfo.premultipliedLast.rawValue
                                                | CGBitmapInfo.byteOrder32Big.rawValue),
                       provider: provider, decode: nil, shouldInterpolate: true, intent: .defaultIntent)
    }
}

struct CoreAtlasView: View {
    let result: RadarResult?
    let received: Date?
    @State private var atlas = CoreAtlas()

    var body: some View {
        // One frame per second keeps the clocks and the stale label current; no request is made here.
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            VStack(alignment: .leading, spacing: 4) {
                if let image = atlas.frame(result: result, received: received) {
                    Image(decorative: image, scale: 1).resizable().interpolation(.high)
                        .aspectRatio(CGSize(width: 1440, height: 900), contentMode: .fit)
                } else {
                    Text("Shared renderer unavailable. No data shown.").foregroundStyle(.secondary)
                }
                if !atlas.accepted {
                    Text("Shared core rejected the latest snapshot; earlier core data, if any, is kept.").font(.caption).foregroundStyle(.orange)
                }
            }
        }
    }
}
