import Foundation

// Private-beta atlas layout for Cloudflare Radar aggregates. Provider rows rank origin→target
// locations; the map shows one marker per origin at an approximate centroid. No individual events,
// routes or summed totals are derived; values are shown exactly as the provider returned them.

struct GeoPoint: Equatable { let lat: Double; let lon: Double }

enum CountryCentroids {
    /// Approximate geographic centroids in degrees. Reference geometry for placement only, not telemetry.
    /// Codes missing here are listed but not placed on the map.
    static let table: [String: GeoPoint] = [
        "US": .init(lat: 39.8, lon: -98.6), "CA": .init(lat: 56.1, lon: -106.3), "MX": .init(lat: 23.6, lon: -102.6),
        "BR": .init(lat: -14.2, lon: -51.9), "AR": .init(lat: -38.4, lon: -63.6), "CL": .init(lat: -35.7, lon: -71.5),
        "CO": .init(lat: 4.6, lon: -74.3), "PE": .init(lat: -9.2, lon: -75.0), "VE": .init(lat: 6.4, lon: -66.6),
        "EC": .init(lat: -1.8, lon: -78.2), "BO": .init(lat: -16.3, lon: -63.6), "PY": .init(lat: -23.4, lon: -58.4),
        "UY": .init(lat: -32.5, lon: -55.8), "PA": .init(lat: 8.5, lon: -80.8), "CR": .init(lat: 9.7, lon: -83.8),
        "GT": .init(lat: 15.8, lon: -90.2), "HN": .init(lat: 15.2, lon: -86.2), "DO": .init(lat: 18.7, lon: -70.2),
        "CU": .init(lat: 21.5, lon: -77.8), "PR": .init(lat: 18.2, lon: -66.6),
        "GB": .init(lat: 55.4, lon: -3.4), "IE": .init(lat: 53.4, lon: -8.2), "FR": .init(lat: 46.2, lon: 2.2),
        "DE": .init(lat: 51.2, lon: 10.5), "NL": .init(lat: 52.1, lon: 5.3), "BE": .init(lat: 50.5, lon: 4.5),
        "LU": .init(lat: 49.8, lon: 6.1), "CH": .init(lat: 46.8, lon: 8.2), "AT": .init(lat: 47.5, lon: 14.6),
        "IT": .init(lat: 41.9, lon: 12.6), "ES": .init(lat: 40.5, lon: -3.7), "PT": .init(lat: 39.4, lon: -8.2),
        "SE": .init(lat: 60.1, lon: 18.6), "NO": .init(lat: 60.5, lon: 8.5), "FI": .init(lat: 61.9, lon: 25.7),
        "DK": .init(lat: 56.3, lon: 9.5), "IS": .init(lat: 64.9, lon: -19.0), "PL": .init(lat: 51.9, lon: 19.1),
        "CZ": .init(lat: 49.8, lon: 15.5), "SK": .init(lat: 48.7, lon: 19.7), "HU": .init(lat: 47.2, lon: 19.5),
        "RO": .init(lat: 45.9, lon: 25.0), "BG": .init(lat: 42.7, lon: 25.5), "GR": .init(lat: 39.1, lon: 21.8),
        "RS": .init(lat: 44.0, lon: 21.0), "HR": .init(lat: 45.1, lon: 15.2), "SI": .init(lat: 46.2, lon: 15.0),
        "BA": .init(lat: 43.9, lon: 17.7), "AL": .init(lat: 41.2, lon: 20.2), "MK": .init(lat: 41.6, lon: 21.7),
        "UA": .init(lat: 48.4, lon: 31.2), "BY": .init(lat: 53.7, lon: 28.0), "MD": .init(lat: 47.4, lon: 28.4),
        "LT": .init(lat: 55.2, lon: 23.9), "LV": .init(lat: 56.9, lon: 24.6), "EE": .init(lat: 58.6, lon: 25.0),
        "RU": .init(lat: 61.5, lon: 105.3), "TR": .init(lat: 39.0, lon: 35.2), "CY": .init(lat: 35.1, lon: 33.4),
        "GE": .init(lat: 42.3, lon: 43.4), "AM": .init(lat: 40.1, lon: 45.0), "AZ": .init(lat: 40.1, lon: 47.6),
        "KZ": .init(lat: 48.0, lon: 66.9), "UZ": .init(lat: 41.4, lon: 64.6),
        "IL": .init(lat: 31.0, lon: 34.9), "PS": .init(lat: 31.9, lon: 35.2), "JO": .init(lat: 30.6, lon: 36.2),
        "LB": .init(lat: 33.9, lon: 35.9), "SY": .init(lat: 34.8, lon: 39.0), "IQ": .init(lat: 33.2, lon: 43.7),
        "IR": .init(lat: 32.4, lon: 53.7), "SA": .init(lat: 23.9, lon: 45.1), "AE": .init(lat: 23.4, lon: 53.8),
        "QA": .init(lat: 25.4, lon: 51.2), "KW": .init(lat: 29.3, lon: 47.5), "BH": .init(lat: 26.0, lon: 50.6),
        "OM": .init(lat: 21.5, lon: 55.9), "YE": .init(lat: 15.6, lon: 48.5),
        "EG": .init(lat: 26.8, lon: 30.8), "LY": .init(lat: 26.3, lon: 17.2), "TN": .init(lat: 33.9, lon: 9.5),
        "DZ": .init(lat: 28.0, lon: 1.7), "MA": .init(lat: 31.8, lon: -7.1), "NG": .init(lat: 9.1, lon: 8.7),
        "GH": .init(lat: 7.9, lon: -1.0), "CI": .init(lat: 7.5, lon: -5.5), "SN": .init(lat: 14.5, lon: -14.5),
        "KE": .init(lat: 0.0, lon: 37.9), "ET": .init(lat: 9.1, lon: 40.5), "TZ": .init(lat: -6.4, lon: 34.9),
        "UG": .init(lat: 1.4, lon: 32.3), "ZA": .init(lat: -30.6, lon: 22.9), "AO": .init(lat: -11.2, lon: 17.9),
        "CM": .init(lat: 7.4, lon: 12.4), "CD": .init(lat: -4.0, lon: 21.8), "ZW": .init(lat: -19.0, lon: 29.2),
        "MZ": .init(lat: -18.7, lon: 35.5),
        "IN": .init(lat: 20.6, lon: 79.0), "PK": .init(lat: 30.4, lon: 69.3), "BD": .init(lat: 23.7, lon: 90.4),
        "LK": .init(lat: 7.9, lon: 80.8), "NP": .init(lat: 28.4, lon: 84.1), "CN": .init(lat: 35.9, lon: 104.2),
        "HK": .init(lat: 22.3, lon: 114.2), "MO": .init(lat: 22.2, lon: 113.5), "TW": .init(lat: 23.7, lon: 121.0),
        "JP": .init(lat: 36.2, lon: 138.3), "KR": .init(lat: 35.9, lon: 127.8), "KP": .init(lat: 40.3, lon: 127.5),
        "MN": .init(lat: 46.9, lon: 103.8), "VN": .init(lat: 14.1, lon: 108.3), "TH": .init(lat: 15.9, lon: 101.0),
        "MY": .init(lat: 4.2, lon: 102.0), "SG": .init(lat: 1.35, lon: 103.8), "ID": .init(lat: -0.8, lon: 113.9),
        "PH": .init(lat: 12.9, lon: 121.8), "KH": .init(lat: 12.6, lon: 105.0), "MM": .init(lat: 21.9, lon: 96.0),
        "LA": .init(lat: 19.9, lon: 102.5), "AU": .init(lat: -25.3, lon: 133.8), "NZ": .init(lat: -40.9, lon: 174.9),
    ]
    static func point(for alpha2: String) -> GeoPoint? { table[alpha2.uppercased()] }
}

/// Same equirectangular layout as the stable renderer, scaled to an arbitrary map rectangle.
func projectEquirectangular(_ p: GeoPoint, width: Double, height: Double) -> (x: Double, y: Double) {
    let lon = min(180, max(-180, p.lon)), lat = min(90, max(-90, p.lat))
    return ((lon + 180) / 360 * width, (90 - lat) / 180 * height)
}

enum AtlasFreshness: Equatable { case noData, empty, current, stale }
/// Matches the existing beta view: a snapshot older than 30 minutes since receipt is stale.
func atlasFreshness(result: RadarResult?, received: Date?, now: Date,
                    staleAfter: TimeInterval = 1800) -> AtlasFreshness {
    guard let result, let received else { return .noData }
    if result.top_0.isEmpty { return .empty }
    return now.timeIntervalSince(received) > staleAfter ? .stale : .current
}

/// Shows the provider's value string unchanged; only PERCENTAGE gets a unit suffix.
func atlasValueLabel(_ raw: String, normalization: String) -> String {
    normalization.uppercased() == "PERCENTAGE" ? raw + "%" : raw + " (" + normalization + ")"
}

struct AtlasMarker: Identifiable {
    let id: Int            // provider row index; repeated provider rows stay distinct
    let alpha2: String
    let name: String
    let targetAlpha2: String?   // nil when the provider row carries no target location
    let targetName: String?
    let rawValue: String
    let value: Double
    let point: GeoPoint?   // nil: listed only, not placed on the map
    let scale: Double      // sqrt(value / largest value): marker area proportional to provider value
}
func atlasMarkers(_ rows: [RadarRow]) -> [AtlasMarker] {
    let values = rows.map { Double($0.value) ?? 0 }
    let largest = values.max() ?? 0
    return displayRows(rows).map { item in
        let value = values[item.index]
        return AtlasMarker(id: item.index, alpha2: item.row.originCountryAlpha2,
                           name: item.row.originCountryName, targetAlpha2: item.row.targetCountryAlpha2,
                           targetName: item.row.targetCountryName, rawValue: item.row.value, value: value,
                           point: CountryCentroids.point(for: item.row.originCountryAlpha2),
                           scale: largest > 0 ? (value / largest).squareRoot() : 0)
    }
}

/// "BR → US" when the provider supplied a target; otherwise says so instead of guessing.
func atlasRowLabel(_ marker: AtlasMarker) -> String {
    marker.alpha2 + " → " + (marker.targetAlpha2 ?? "target not supplied")
}

/// One map marker per origin location. Rows are not summed: the marker is sized by that origin's
/// largest single row, and rowCount says how many ranked rows share the origin.
struct AtlasOriginMarker: Identifiable {
    let alpha2: String
    let point: GeoPoint?
    let largestValue: Double
    let rowCount: Int
    let scale: Double
    var id: String { alpha2 }
}
func atlasOriginMarkers(_ markers: [AtlasMarker]) -> [AtlasOriginMarker] {
    var order: [String] = []
    var byOrigin: [String: [AtlasMarker]] = [:]
    for marker in markers {
        let code = marker.alpha2.uppercased()
        if byOrigin[code] == nil { order.append(code) }
        byOrigin[code, default: []].append(marker)
    }
    return order.map { code in
        let rows = byOrigin[code]!
        let top = rows.max { $0.value < $1.value }!
        return AtlasOriginMarker(alpha2: code, point: top.point, largestValue: top.value,
                                 rowCount: rows.count, scale: top.scale)
    }
}

/// Parses GeoJSON Polygon/MultiPolygon land rings (the build copies assets/land.json read-only).
func parseLandRings(_ data: Data) -> [[GeoPoint]] {
    guard data.count <= 5_000_000,
          let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
          let features = root["features"] as? [[String: Any]] else { return [] }
    var rings: [[GeoPoint]] = []
    for feature in features {
        guard let geometry = feature["geometry"] as? [String: Any],
              let type = geometry["type"] as? String else { continue }
        let polygons: [Any]
        switch type {
        case "Polygon": polygons = [geometry["coordinates"] as Any]
        case "MultiPolygon": polygons = geometry["coordinates"] as? [Any] ?? []
        default: continue
        }
        for polygon in polygons {
            for ring in polygon as? [[[Double]]] ?? [] {
                let points = ring.compactMap { $0.count >= 2 ? GeoPoint(lat: $0[1], lon: $0[0]) : nil }
                if points.count >= 3 { rings.append(points) }
            }
        }
    }
    return rings
}
