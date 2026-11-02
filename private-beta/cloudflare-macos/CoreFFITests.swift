import Foundation
// Swift -> shared core boundary tests. Offline: synthetic fixtures, no network, no Keychain.
// Run (after cargo build --release -p threat-atlas-core):
// xcrun swiftc -parse-as-library -import-objc-header RadarCoreFFI.h RadarCore.swift CoreAtlasView.swift CoreFFITests.swift \
//   ../../target/release/libthreat_atlas_core.a -framework SwiftUI -framework Security -framework CoreFoundation \
//   -framework SystemConfiguration -liconv -o /private/tmp/radar-core-ffi-tests && /private/tmp/radar-core-ffi-tests
func check(_ ok: Bool, _ what: String) { precondition(ok, what); print("ok  " + what) }

@main struct CoreFFITests {
    static func main() throws {
        // Synthetic fixture only: never presented as telemetry.
        let fixture = Data(#"{"success":true,"result":{"meta":{"lastUpdated":"2026-01-01T00:00:00Z","normalization":"PERCENTAGE","dateRange":[{"startTime":"2025-12-31T00:00:00Z","endTime":"2026-01-01T00:00:00Z"}]},"top_0":[{"originCountryAlpha2":"BR","originCountryName":"Brazil","targetCountryAlpha2":"US","targetCountryName":"United States","value":"7.4"},{"originCountryAlpha2":"HK","originCountryName":"Hong Kong","value":"2.1"}]}}"#.utf8)
        let parsed = try parseRadar(fixture)
        let body = try XCTUnwrap(coreBody(parsed))
        let echoed = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        let rows = (echoed?["result"] as? [String: Any])?["top_0"] as? [[String: Any]]
        check(rows?.count == 2 && rows?[0]["targetCountryAlpha2"] as? String == "US", "Swift body keeps provider rows and targets")
        check(rows?[1]["targetCountryAlpha2"] == nil, "missing target stays missing (not invented)")

        let session = ta_radar_new()
        check(session != nil, "core session created")
        let set = { (data: Data) in
            data.withUnsafeBytes { ta_radar_set(session, $0.bindMemory(to: UInt8.self).baseAddress, $0.count, 1_000) }
        }
        check(set(body) == 0, "core accepts the Swift-built body")
        check(set(Data(#"{"success":false}"#.utf8)) == -1, "core rejects an unsuccessful envelope")
        check(ta_radar_set(session, nil, 0, 0) == -1, "core rejects a null body")
        check(ta_radar_frame(session) != nil && ta_width() == 1440 && ta_height() == 900, "core renders a 1440x900 frame")
        ta_radar_drop(session)

        let atlas = CoreAtlas()
        let image = atlas.frame(result: parsed, received: Date(timeIntervalSince1970: 1_767_225_600))
        check(image?.width == 1440 && atlas.accepted, "CoreAtlas hands the snapshot in once and returns an image")
        check(CoreAtlas().frame(result: nil, received: nil) != nil, "no-data frame renders without a snapshot")
        print("PASS: Swift/core boundary")
    }
}
func XCTUnwrap<T>(_ value: T?) throws -> T {
    guard let value else { throw NSError(domain: "CoreFFITests", code: 1) }
    return value
}
