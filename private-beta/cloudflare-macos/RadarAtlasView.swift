import SwiftUI

// Private-beta atlas view: Cloudflare Radar aggregate country values drawn in the Threat Atlas
// visual language (palette and equirectangular land map of crates/core/src/render.rs, not shared code).
// Markers are per origin location only; origin→target rows are listed as the provider ranks them.
// No events, connecting lines, routes, summed totals or animation of arrivals.

enum AtlasPalette {
    static func rgb(_ r: Double, _ g: Double, _ b: Double) -> Color { Color(red: r / 255, green: g / 255, blue: b / 255) }
    static let background = rgb(5, 12, 21)
    static let panel = rgb(10, 23, 36)
    static let grid = rgb(22, 43, 57)
    static let land = rgb(22, 49, 63)
    static let coast = rgb(48, 90, 106)
    static let title = rgb(223, 241, 249)
    static let muted = rgb(100, 139, 159)
    static let cyan = rgb(68, 220, 225)
    static let amber = rgb(255, 190, 82)
}

struct RadarAtlasView: View {
    let result: RadarResult?
    let received: Date?
    private static let land: [[GeoPoint]] = Bundle.main.url(forResource: "land", withExtension: "json")
        .flatMap { try? Data(contentsOf: $0) }.map(parseLandRings) ?? []

    var body: some View {
        // Re-evaluate freshness on a clock so a cached snapshot turns STALE without a new request.
        TimelineView(.periodic(from: .now, by: 30)) { context in
            content(state: atlasFreshness(result: result, received: received, now: context.date))
        }
    }

    private func content(state: AtlasFreshness) -> some View {
        let markers = result.map { atlasMarkers($0.top_0) } ?? []
        let normalization = result?.meta.normalization ?? ""
        return VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text("THREAT ATLAS").font(.system(size: 26, weight: .bold, design: .monospaced)).foregroundStyle(AtlasPalette.title)
                Text("CLOUDFLARE RADAR / TOP LAYER 3 ATTACKS · ORIGIN → TARGET").font(.system(size: 12, design: .monospaced)).foregroundStyle(AtlasPalette.muted)
                Spacer()
                stateBadge(state)
            }
            HStack(alignment: .top, spacing: 14) {
                map(markers, state: state)
                list(markers, normalization: normalization, state: state).frame(width: 300)
            }
            footer(state)
        }
        .padding(16).background(AtlasPalette.background)
    }

    private func stateBadge(_ state: AtlasFreshness) -> some View {
        let (label, color): (String, Color) = switch state {
        case .noData: ("NO DATA", AtlasPalette.muted)
        case .empty: ("EMPTY RESPONSE", AtlasPalette.muted)
        case .current: ("CACHED SNAPSHOT", AtlasPalette.cyan)
        case .stale: ("STALE CACHE", AtlasPalette.amber)
        }
        return Text(label).font(.system(size: 12, weight: .bold, design: .monospaced)).foregroundStyle(color)
            .padding(.horizontal, 8).padding(.vertical, 3).overlay(RoundedRectangle(cornerRadius: 3).stroke(color))
    }

    private func map(_ markers: [AtlasMarker], state: AtlasFreshness) -> some View {
        Canvas { ctx, size in
            let w = size.width, h = size.height
            func point(_ p: GeoPoint) -> CGPoint {
                let xy = projectEquirectangular(p, width: w, height: h); return CGPoint(x: xy.x, y: xy.y)
            }
            ctx.fill(Path(CGRect(origin: .zero, size: size)), with: .color(AtlasPalette.panel))
            var grid = Path()
            for lon in stride(from: -180.0, through: 180, by: 30) {
                grid.move(to: point(.init(lat: 90, lon: lon))); grid.addLine(to: point(.init(lat: -90, lon: lon)))
            }
            for lat in stride(from: -90.0, through: 90, by: 30) {
                grid.move(to: point(.init(lat: lat, lon: -180))); grid.addLine(to: point(.init(lat: lat, lon: 180)))
            }
            ctx.stroke(grid, with: .color(AtlasPalette.grid.opacity(0.7)), lineWidth: 1)
            var land = Path()
            for ring in Self.land {
                land.move(to: point(ring[0])); for p in ring.dropFirst() { land.addLine(to: point(p)) }; land.closeSubpath()
            }
            ctx.fill(land, with: .color(AtlasPalette.land), style: FillStyle(eoFill: true))
            ctx.stroke(land, with: .color(AtlasPalette.coast.opacity(0.86)), lineWidth: 0.7)

            let dim = state == .stale ? 0.5 : 1.0
            let maxRadius = min(w, h) * 0.07
            // One marker per origin; largest first so smaller ones stay visible on top.
            let origins = atlasOriginMarkers(markers).sorted { $0.largestValue > $1.largestValue }
            for origin in origins {
                guard let geo = origin.point else { continue }
                let c = point(geo), r = 3 + origin.scale * maxRadius
                let circle = Path(ellipseIn: CGRect(x: c.x - r, y: c.y - r, width: 2 * r, height: 2 * r))
                ctx.fill(circle, with: .color(AtlasPalette.amber.opacity(0.28 * dim)))
                ctx.stroke(circle, with: .color(AtlasPalette.amber.opacity(0.9 * dim)), lineWidth: 1.2)
            }
            for origin in origins.prefix(8) {
                guard let geo = origin.point else { continue }
                let c = point(geo)
                let label = origin.rowCount > 1 ? "\(origin.alpha2) ×\(origin.rowCount)" : origin.alpha2
                ctx.draw(Text(label).font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .foregroundColor(AtlasPalette.title.opacity(dim)), at: CGPoint(x: c.x, y: c.y - 3 - origin.scale * maxRadius - 8))
            }
            if Self.land.isEmpty {
                ctx.draw(Text("LAND MAP UNAVAILABLE IN BUNDLE").font(.system(size: 11, design: .monospaced))
                    .foregroundColor(AtlasPalette.muted), at: CGPoint(x: w / 2, y: 14))
            }
            let notice: String? = switch state {
            case .noData: "NO CLOUDFLARE DATA RECEIVED · NO SAMPLE TELEMETRY SHOWN"
            case .empty: "PROVIDER RETURNED NO COUNTRY ROWS"
            default: nil
            }
            if let notice {
                ctx.draw(Text(notice).font(.system(size: 14, weight: .semibold, design: .monospaced))
                    .foregroundColor(AtlasPalette.muted), at: CGPoint(x: w / 2, y: h / 2))
            }
        }
        .aspectRatio(2, contentMode: .fit)
        .frame(minWidth: 600)
    }

    private func list(_ markers: [AtlasMarker], normalization: String, state: AtlasFreshness) -> some View {
        let largest = markers.map(\.value).max() ?? 0
        return VStack(alignment: .leading, spacing: 6) {
            Text("TOP ROWS · ORIGIN → TARGET").font(.system(size: 14, weight: .semibold, design: .monospaced)).foregroundStyle(AtlasPalette.cyan)
            Text("Provider rank · past-day aggregate · \(markers.count) rows, scroll for more").font(.system(size: 10, design: .monospaced)).foregroundStyle(AtlasPalette.muted)
            ScrollView {
                VStack(alignment: .leading, spacing: 5) {
                    ForEach(markers) { marker in
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Text("\(marker.id + 1). \(atlasRowLabel(marker))").foregroundStyle(AtlasPalette.title).lineLimit(1)
                                Spacer()
                                Text(atlasValueLabel(marker.rawValue, normalization: normalization)).foregroundStyle(AtlasPalette.amber)
                            }
                            Text("\(marker.name) → \(marker.targetName ?? "target not in provider row")")
                                .font(.system(size: 9, design: .monospaced)).foregroundStyle(AtlasPalette.muted).lineLimit(1)
                            GeometryReader { g in
                                Rectangle().fill(AtlasPalette.amber.opacity(state == .stale ? 0.35 : 0.7))
                                    .frame(width: largest > 0 ? g.size.width * marker.value / largest : 0)
                            }.frame(height: 3)
                            if marker.point == nil {
                                Text("not placed: no centroid for this code").font(.system(size: 9, design: .monospaced)).foregroundStyle(AtlasPalette.muted)
                            }
                        }.font(.system(size: 11, design: .monospaced))
                    }
                }
            }
        }
        .padding(10).background(AtlasPalette.panel)
    }

    private func footer(_ state: AtlasFreshness) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("CLOUDFLARE RADAR · TOP LAYER 3 ATTACKS, ORIGIN → TARGET LOCATION · AGGREGATE VALUES, NOT INDIVIDUAL ATTACKS · NO ROUTES DRAWN")
            Text("Each value is one row's share of all layer 3 attacks · rows are not summed")
            if let result {
                Text("Normalization: \(result.meta.normalization) · Provider updated: \(result.meta.lastUpdated)")
                ForEach(result.meta.dateRange.indices, id: \.self) { i in
                    Text("Window: \(result.meta.dateRange[i].startTime) – \(result.meta.dateRange[i].endTime)")
                }
            }
            if let received {
                Text("Received: \(received.formatted(.dateTime.year().month().day().hour().minute().timeZone()))\(state == .stale ? " · STALE CACHE" : "")")
            }
            Text("One marker per origin · area ∝ that origin's largest row relative to the largest row · ×n = origin in n rows · approximate country centroids")
        }
        .font(.system(size: 10, design: .monospaced)).foregroundStyle(AtlasPalette.muted)
    }
}
