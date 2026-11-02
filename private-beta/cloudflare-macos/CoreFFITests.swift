import Foundation
// Swift -> shared core boundary tests. Offline: synthetic fixtures, no network, no Keychain.
// Run (after build.sh, which builds the core per architecture):
// xcrun swiftc -parse-as-library -import-objc-header RadarCoreFFI.h RadarCore.swift CoreAtlasView.swift CoreFFITests.swift \
//   ../../target/aarch64-apple-darwin/release/libthreat_atlas_core.a -framework SwiftUI -framework Security -framework CoreFoundation \
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

        // CoreAtlas opens the live GreyNoise feed (ta_soc_new), so it is not created in offline tests;
        // its SOC behaviour is covered by the Rust soc tests. Check the offline pieces around it.
        let fit = FrameFit(CGSize(width: 1000, height: 1000))   // letterboxed vertically
        let corner = fit.framePoint(CGPoint(x: 0, y: fit.origin.y))
        check(abs(corner.x) < 0.001 && abs(corner.y) < 0.001 && fit.origin.x == 0, "view point maps to frame origin")
        let far = fit.framePoint(CGPoint(x: 1000, y: fit.origin.y + 900 * fit.scale))
        check(abs(far.x - 1440) < 0.01 && abs(far.y - 900) < 0.01, "view point maps to frame corner")
        let info = try JSONDecoder().decode(CountryInfo.self, from: Data(#"{"index":3,"code":"NL","name":"Netherlands","window_minutes":5,"malicious":1,"suspicious":2,"benign":3,"radar_rows":[{"rank":2,"target":null,"value":"4.4%"}]}"#.utf8))
        check(info.code == "NL" && info.benign == 3 && info.radar_rows.first?.target == nil, "core inspect JSON decodes, missing target stays nil")
        print("PASS: Swift/core boundary")
    }
}
func XCTUnwrap<T>(_ value: T?) throws -> T {
    guard let value else { throw NSError(domain: "CoreFFITests", code: 1) }
    return value
}
