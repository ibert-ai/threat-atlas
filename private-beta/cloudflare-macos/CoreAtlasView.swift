import SwiftUI
import CoreGraphics

// Live SOC view drawn by the shared Rust core (crates/core, ta_soc_*): the screensaver's renderer,
// map, country outlines and GreyNoise feed, plus the Cloudflare Radar snapshot from this app.
// This file hands data in, shows frames and adds calm interaction: hover details, click focus,
// severity toggles, Calm/Still motion and pause. Severity colours match the core exactly.

/// Rebuilds a provider-shaped body from the parsed snapshot so the core applies its own validation.
func coreBody(_ result: RadarResult) -> Data? {
    struct Body: Encodable { let success = true; let result: RadarResult }
    return try? JSONEncoder().encode(Body(result: result))
}

enum Severity: Int, CaseIterable {
    case malicious, suspicious, benign
    var name: String { ["Malicious", "Suspicious", "Benign"][rawValue] }
    var color: Color {
        [Color(red: 235 / 255, green: 87 / 255, blue: 87 / 255),
         Color(red: 242 / 255, green: 201 / 255, blue: 76 / 255),
         Color(red: 72 / 255, green: 199 / 255, blue: 142 / 255)][rawValue]
    }
}
/// Arc motion. Realtime (screensaver-like) is the default per Robert; Calm and Still remain options.
enum Motion: UInt32, CaseIterable {
    case calm = 0, still = 1, realtime = 2
    var name: String { ["Calm", "Still", "Realtime"][Int(rawValue)] }
    /// Seconds between frames: Calm needs slow fades, Realtime moving heads, Still only the clocks.
    var frameInterval: Double { [0.125, 1, 1.0 / 15][Int(rawValue)] }
}
/// Layout theme around the shared map (ATLAS-SOC-LAYOUT-001). Classic stays the default;
/// the choice is remembered in user defaults.
enum LayoutTheme: Int, CaseIterable {
    case classic = 0, dashboard = 1
    var name: String { ["Classic", "Dashboard"][rawValue] }
}
let infoColor = Color(red: 116 / 255, green: 151 / 255, blue: 189 / 255)

/// Country details from the core's hover inspection (counts are received records, not unique attacks).
struct CountryInfo: Decodable, Equatable {
    struct RadarRow: Decodable, Equatable { let rank: Int; let target: String?; let value: String }
    let code: String
    let name: String
    let window_minutes: Int
    let malicious: Int
    let suspicious: Int
    let benign: Int
    let radar_rows: [RadarRow]
}

final class CoreAtlas {
    static let size = CGSize(width: 1440, height: 900)
    private let session = ta_soc_new()
    private var handed: Date?            // receipt time of the Radar snapshot last given to the core
    private(set) var accepted = true     // false when the core rejected that snapshot
    private(set) var last: CGImage?
    private(set) var focused: Int32 = -1
    deinit { ta_soc_drop(session) }

    func setOptions(severities: [Bool], motion: Motion) {
        let mask = severities.enumerated().reduce(UInt32(0)) { $0 | ($1.element ? 1 << UInt32($1.offset) : 0) }
        ta_soc_set_options(session, mask, motion.rawValue)
    }
    func setTheme(_ theme: LayoutTheme) { ta_soc_set_theme(session, UInt32(theme.rawValue)) }
    func setRadarLayer(on: Bool, hidden: Set<String>) {
        let codes = Array(hidden.sorted().joined(separator: ",").utf8)
        codes.withUnsafeBufferPointer { ta_soc_set_radar_layer(session, on ? 1 : 0, $0.baseAddress, $0.count) }
    }
    func toggleFocus(at point: CGPoint) { focused = ta_soc_focus_at(session, Float(point.x), Float(point.y)) }
    func clearFocus() { focused = ta_soc_focus_at(session, -1, -1) }
    func inspect(at point: CGPoint) -> CountryInfo? {
        var buffer = [UInt8](repeating: 0, count: 8192)
        let count = ta_soc_inspect(session, Float(point.x), Float(point.y), &buffer, buffer.count)
        guard count > 0 else { return nil }
        return try? JSONDecoder().decode(CountryInfo.self, from: Data(buffer[0..<count]))
    }
    /// Gives a new Radar snapshot to the core once, then renders the current frame.
    func frame(result: RadarResult?, received: Date?) -> CGImage? {
        guard let session else { return nil }
        if let result, let received, received != handed {
            handed = received
            let ms = UInt64(max(0, received.timeIntervalSince1970 * 1000))
            accepted = coreBody(result).map { body in
                body.withUnsafeBytes { raw in
                    ta_soc_set_radar(session, raw.bindMemory(to: UInt8.self).baseAddress, raw.count, ms) == 0
                }
            } ?? false
        }
        guard let pixels = ta_soc_frame(session) else { return nil }
        let width = Int(ta_width()), height = Int(ta_height())
        // Copy now: the core reuses its buffer on the next frame.
        guard let provider = CGDataProvider(data: Data(bytes: pixels, count: width * height * 4) as CFData)
        else { return nil }
        last = CGImage(width: width, height: height, bitsPerComponent: 8, bitsPerPixel: 32,
                       bytesPerRow: width * 4, space: CGColorSpaceCreateDeviceRGB(),
                       bitmapInfo: CGBitmapInfo(rawValue: CGImageAlphaInfo.premultipliedLast.rawValue
                                                | CGBitmapInfo.byteOrder32Big.rawValue),
                       provider: provider, decode: nil, shouldInterpolate: true, intent: .defaultIntent)
        return last
    }
}

/// Aspect-fit placement of the 1440x900 frame inside a view, and the inverse mapping for the mouse.
struct FrameFit {
    let scale: CGFloat, origin: CGPoint
    init(_ size: CGSize) {
        scale = min(size.width / CoreAtlas.size.width, size.height / CoreAtlas.size.height)
        origin = CGPoint(x: (size.width - CoreAtlas.size.width * scale) / 2,
                         y: (size.height - CoreAtlas.size.height * scale) / 2)
    }
    func framePoint(_ p: CGPoint) -> CGPoint { CGPoint(x: (p.x - origin.x) / scale, y: (p.y - origin.y) / scale) }
}

struct CoreAtlasView: View {
    let result: RadarResult?
    let received: Date?
    @State private var atlas = CoreAtlas()
    @State private var severities = [true, true, true]
    @State private var motion = Motion.realtime
    @AppStorage("atlasSOC.layoutTheme") private var theme = LayoutTheme.classic
    @State private var paused = false
    @State private var focused = false
    @State private var hover: CountryInfo?
    @State private var hoverAt = CGPoint.zero
    @State private var radarOn = true
    @State private var hidden = Set<String>()

    /// Cloudflare origins in provider order: code, name and the value of its largest row (never summed).
    private var origins: [(code: String, name: String, value: String)] {
        guard let rows = result?.top_0 else { return [] }
        var seen: [String: (name: String, best: Double, value: String)] = [:]
        var order: [String] = []
        for row in rows {
            let code = row.originCountryAlpha2.trimmingCharacters(in: .whitespaces).uppercased()
            let value = Double(row.value) ?? 0
            if seen[code] == nil { order.append(code) }
            if value >= (seen[code]?.best ?? -1) { seen[code] = (row.originCountryName, value, row.value) }
        }
        let unit = result?.meta.normalization.uppercased() == "PERCENTAGE" ? "%" : ""
        return order.map { (code: $0, name: seen[$0]!.name, value: seen[$0]!.value + unit) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            controls
            // Calm 8 frames/s, Realtime 15 frames/s; Still or paused 1 frame/s for the clocks.
            TimelineView(.periodic(from: .now, by: paused ? 1 : motion.frameInterval)) { _ in
                let image = paused ? atlas.last : atlas.frame(result: result, received: received)
                GeometryReader { geo in
                    let fit = FrameFit(geo.size)
                    ZStack(alignment: .topLeading) {
                        if let image {
                            Image(decorative: image, scale: 1).resizable().interpolation(.high)
                                .frame(width: CoreAtlas.size.width * fit.scale, height: CoreAtlas.size.height * fit.scale)
                                .offset(x: fit.origin.x, y: fit.origin.y)
                        } else {
                            Text("Shared renderer unavailable. No data shown.").foregroundStyle(.secondary)
                        }
                        if let hover {
                            CountryCard(info: hover, focused: focused)
                                .offset(x: min(hoverAt.x + 16, max(0, geo.size.width - 300)),
                                        y: min(hoverAt.y + 16, max(0, geo.size.height - 190)))
                                .allowsHitTesting(false)
                        }
                    }
                    .contentShape(Rectangle())
                    .onContinuousHover { phase in
                        switch phase {
                        case .active(let location):
                            hoverAt = location
                            let info = atlas.inspect(at: fit.framePoint(location))
                            if info != hover { hover = info }
                        case .ended:
                            hover = nil
                        }
                    }
                    .onTapGesture { location in
                        atlas.toggleFocus(at: fit.framePoint(location))
                        focused = atlas.focused >= 0
                    }
                }
            }
            if !atlas.accepted {
                Text("Shared core rejected the latest Radar snapshot; earlier core data, if any, is kept.")
                    .font(.caption).foregroundStyle(.orange)
            }
        }
        .onAppear {
            atlas.setOptions(severities: severities, motion: motion)
            atlas.setTheme(theme)
            atlas.setRadarLayer(on: radarOn, hidden: hidden)
        }
        .onChange(of: theme) { _, value in atlas.setTheme(value) }
        .onChange(of: radarOn) { _, value in atlas.setRadarLayer(on: value, hidden: hidden) }
        .onChange(of: hidden) { _, value in atlas.setRadarLayer(on: radarOn, hidden: value) }
        .onChange(of: severities) { _, value in atlas.setOptions(severities: value, motion: motion) }
        .onChange(of: motion) { _, value in atlas.setOptions(severities: severities, motion: value) }
    }

    private var controls: some View {
        HStack(spacing: 10) {
            ForEach(Severity.allCases, id: \.rawValue) { severity in
                Toggle(isOn: $severities[severity.rawValue]) {
                    HStack(spacing: 5) {
                        Circle().fill(severity.color).frame(width: 9, height: 9)
                        Text(severity.name)
                    }
                }
                .toggleStyle(.button)
            }
            Divider().frame(height: 18)
            Picker("Motion", selection: $motion) {
                ForEach(Motion.allCases, id: \.rawValue) { Text($0.name).tag($0) }
            }
            .pickerStyle(.segmented).frame(width: 230).labelsHidden()
            .help("Realtime (default): up to 40 arcs/s as records arrive. Calm: few slow arcs. Still: no arcs.")
            Button(paused ? "Resume" : "Pause") { paused.toggle() }
            Divider().frame(height: 18)
            Picker("Layout", selection: $theme) {
                ForEach(LayoutTheme.allCases, id: \.rawValue) { Text($0.name).tag($0) }
            }
            .pickerStyle(.segmented).frame(width: 170).labelsHidden()
            .help("Classic (default) or Dashboard layout. Same map and data; remembered between launches.")
            Divider().frame(height: 18)
            Toggle(isOn: $radarOn) {
                HStack(spacing: 5) {
                    Image(systemName: "circle.circle").foregroundStyle(infoColor)
                    Text("Cloudflare")
                }
            }
            .toggleStyle(.button)
            .help("Show or hide the whole Cloudflare Radar icon layer")
            Menu("Countries (\(origins.count - hidden.intersection(origins.map(\.code)).count)/\(origins.count))") {
                Button("Show all") { hidden.removeAll() }
                Button("Hide all") { hidden = Set(origins.map(\.code)) }
                Divider()
                ForEach(origins, id: \.code) { origin in
                    Toggle("\(origin.code)  \(origin.name)  \(origin.value)", isOn: Binding(
                        get: { !hidden.contains(origin.code) },
                        set: { visible in if visible { hidden.remove(origin.code) } else { hidden.insert(origin.code) } }))
                }
            }
            .fixedSize()
            .disabled(!radarOn || origins.isEmpty)
            .help("Show or hide individual Cloudflare origin countries (their targets follow)")
            if focused {
                Button("Clear focus") { atlas.clearFocus(); focused = false }
            }
            Spacer()
            Text(paused ? "PAUSED · live feed keeps running" : "Hover for details · click a country to focus").lineLimit(1)
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}

struct CountryCard: View {
    let info: CountryInfo
    let focused: Bool
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("\(info.name) (\(info.code))").font(.headline)
            Text("GreyNoise, last \(info.window_minutes) min · received records, not unique attacks")
                .font(.caption2).foregroundStyle(.secondary)
            HStack(spacing: 12) {
                count(info.malicious, .malicious)
                count(info.suspicious, .suspicious)
                count(info.benign, .benign)
            }
            if info.radar_rows.isEmpty {
                Text("Cloudflare Radar: no top row for this origin").font(.caption).foregroundStyle(infoColor)
            } else {
                Text("Cloudflare Radar (aggregate, as origin)").font(.caption).foregroundStyle(infoColor)
                ForEach(info.radar_rows, id: \.rank) { row in
                    Text("#\(row.rank) → \(row.target ?? "target not supplied") · \(row.value)")
                        .font(.caption.monospaced()).foregroundStyle(infoColor)
                }
            }
            Text(focused ? "Click to switch focus; click the focused country to clear" : "Click to focus this country")
                .font(.caption2).foregroundStyle(.secondary)
        }
        .padding(10)
        .frame(width: 280, alignment: .leading)
        .background(Color(red: 10 / 255, green: 23 / 255, blue: 36 / 255).opacity(0.94))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(infoColor.opacity(0.5)))
    }
    private func count(_ value: Int, _ severity: Severity) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("\(value)").font(.title3.monospacedDigit()).foregroundStyle(severity.color)
            Text(severity.name).font(.caption2).foregroundStyle(.secondary)
        }
    }
}
