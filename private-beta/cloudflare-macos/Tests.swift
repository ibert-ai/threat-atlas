import Foundation
@main struct CoreTests {
    static func main() throws {
        let now = Date(timeIntervalSince1970: 0)
        precondition(PollPolicy.delay(status: 429, retryAfter: "3600", reset: nil, failures: 1, now: now, jitter: 0) == 3600)
        precondition(PollPolicy.delay(status: 429, retryAfter: "Thu, 01 Jan 1970 01:00:00 GMT", reset: nil, failures: 1, now: now, jitter: 0) == 3600)
        precondition(PollPolicy.delay(status: 200, retryAfter: nil, reset: "\"default\";r=0;t=2000", failures: 0, now: now, jitter: 0) == 2005)
        precondition(PollPolicy.delay(status: 500, retryAfter: "invalid", reset: nil, failures: 20, now: now, jitter: 0) == 21600)
        precondition(PollPolicy.delay(status: 500, retryAfter: nil, reset: nil, failures: 20, now: now, jitter: 30) == 21630)
        precondition(PollPolicy.delay(status: 500, retryAfter: nil, reset: nil, failures: 1, now: now, jitter: 0) >= 900)
        // Synthetic parser fixtures only: never presented as telemetry.
        let valid = Data(#"{"success":true,"result":{"meta":{"lastUpdated":"2026-01-01T00:00:00Z","normalization":"PERCENTAGE","dateRange":[{"startTime":"2025-12-31T00:00:00Z","endTime":"2026-01-01T00:00:00Z"}]},"top_0":[{"originCountryAlpha2":"FR","originCountryName":"France","value":"4.3"}]}}"#.utf8)
        let parsed = try parseRadar(valid)
        precondition(parsed.top_0.first?.value == "4.3")
        let repeated = parsed.top_0 + parsed.top_0
        let display = displayRows(repeated)
        precondition(display.map(\.id) == [0, 1])
        precondition(display.map(\.row.value) == ["4.3", "4.3"])
        for data in [Data(#"{"success":false}"#.utf8), Data("{}".utf8), Data(repeating: 32, count: 2_000_001), Data(String(decoding: valid, as: UTF8.self).replacingOccurrences(of: "4.3", with: "NaN").utf8)] {
            do { _ = try parseRadar(data); fatalError("invalid response accepted") } catch {}
        }
        print("PASS: cooldown floor, numeric/date Retry-After, quota window, bounded backoff, duplicate provider row identity, parser and invalid/oversized payload rejection")
    }
}
