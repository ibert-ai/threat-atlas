import Foundation
// Atlas prototype tests. Separate entry point from Tests.swift; compile with
// RadarCore.swift RadarAtlasCore.swift AtlasTests.swift (see README). Not yet run.
@main struct AtlasTests {
    static func main() throws {
        let center = projectEquirectangular(.init(lat: 0, lon: 0), width: 200, height: 100)
        precondition(center.x == 100 && center.y == 50)
        let corner = projectEquirectangular(.init(lat: 95, lon: -200), width: 200, height: 100)
        precondition(corner.x == 0 && corner.y == 0)
        let far = projectEquirectangular(.init(lat: -90, lon: 180), width: 200, height: 100)
        precondition(far.x == 200 && far.y == 100)

        precondition(atlasValueLabel("4.3", normalization: "PERCENTAGE") == "4.3%")
        precondition(atlasValueLabel("4.3", normalization: "MIN0_MAX") == "4.3 (MIN0_MAX)")

        // Synthetic fixtures only: never presented as telemetry.
        let meta = RadarMeta(lastUpdated: "2026-01-01T00:00:00Z", normalization: "PERCENTAGE",
                             dateRange: [RadarRange(startTime: "2025-12-31T00:00:00Z", endTime: "2026-01-01T00:00:00Z")])
        let rows = [RadarRow(originCountryAlpha2: "FR", originCountryName: "France", value: "16.0"),
                    RadarRow(originCountryAlpha2: "XX", originCountryName: "Unknown", value: "4.0"),
                    RadarRow(originCountryAlpha2: "fr", originCountryName: "France", value: "4.0")]
        let markers = atlasMarkers(rows)
        precondition(markers.count == rows.count, "one marker per provider row; nothing synthesized")
        precondition(markers.map(\.id) == [0, 1, 2])
        precondition(markers.map(\.rawValue) == ["16.0", "4.0", "4.0"], "provider value strings unchanged")
        precondition(markers[0].scale == 1 && markers[1].scale == 0.5)
        precondition(markers[1].point == nil, "unknown code is listed, not placed")
        precondition(markers[2].point == CountryCentroids.point(for: "FR"))
        precondition(atlasMarkers([RadarRow(originCountryAlpha2: "FR", originCountryName: "France", value: "0")])[0].scale == 0)

        let now = Date(timeIntervalSince1970: 10_000)
        let result = RadarResult(meta: meta, top_0: rows)
        precondition(atlasFreshness(result: nil, received: nil, now: now) == .noData)
        precondition(atlasFreshness(result: result, received: nil, now: now) == .noData)
        precondition(atlasFreshness(result: RadarResult(meta: meta, top_0: []), received: now, now: now) == .empty)
        precondition(atlasFreshness(result: result, received: now.addingTimeInterval(-60), now: now) == .current)
        precondition(atlasFreshness(result: result, received: now.addingTimeInterval(-3600), now: now) == .stale)

        let land = Data(#"{"type":"FeatureCollection","features":[{"geometry":{"type":"Polygon","coordinates":[[[0,0],[10,0],[10,10],[0,0]]]}},{"geometry":{"type":"MultiPolygon","coordinates":[[[[20,20],[30,20],[30,30],[20,20]]],[[[40,40],[50,40],[50,50],[40,40]]]]}},{"geometry":{"type":"Point","coordinates":[1,1]}}]}"#.utf8)
        let rings = parseLandRings(land)
        precondition(rings.count == 3 && rings[0][1] == GeoPoint(lat: 0, lon: 10))
        precondition(parseLandRings(Data("{}".utf8)).isEmpty)

        print("PASS: projection bounds, unit labels, one marker per provider row, unplaced codes, freshness states, land ring parsing")
    }
}
