import Foundation

struct RadarEnvelope: Decodable {
    let success: Bool
    let result: RadarResult?
}
struct RadarResult: Codable {
    let meta: RadarMeta
    let top_0: [RadarRow]
}
struct RadarMeta: Codable {
    let lastUpdated: String
    let normalization: String
    let dateRange: [RadarRange]
}
struct RadarRange: Codable { let startTime: String; let endTime: String }
struct RadarRow: Codable {
    let originCountryAlpha2: String
    let originCountryName: String
    let value: String
    // Endpoint ranks origin→target locations; the documented schema lists only origin fields,
    // so target fields are decoded when present and never inferred.
    var targetCountryAlpha2: String? = nil
    var targetCountryName: String? = nil
}
struct RadarDisplayRow: Identifiable {
    let index: Int
    let row: RadarRow
    var id: Int { index }
}
func displayRows(_ rows: [RadarRow]) -> [RadarDisplayRow] {
    rows.enumerated().map { RadarDisplayRow(index: $0.offset, row: $0.element) }
}
func parseRadar(_ data: Data) throws -> RadarResult {
    guard data.count <= 2_000_000 else { throw RadarError.invalidResponse }
    let envelope = try JSONDecoder().decode(RadarEnvelope.self, from: data)
    guard envelope.success, let result = envelope.result,
          result.top_0.count <= 100, !result.meta.dateRange.isEmpty,
          result.top_0.allSatisfy({ Double($0.value).map { $0.isFinite && $0 >= 0 } ?? false })
    else { throw RadarError.invalidResponse }
    return result
}
enum RadarError: Error { case invalidResponse }
struct PollPolicy {
    static let interval: TimeInterval = 900
    static func delay(status: Int, retryAfter: String?, reset: String?, failures: Int,
                      now: Date, jitter: Double = Double.random(in: 0...30)) -> TimeInterval {
        var delay = max(interval, min(21600, 60 * pow(2, Double(min(failures, 9))))) + jitter
        if let raw = retryAfter {
            if let seconds = Double(raw), seconds.isFinite { delay = max(delay, seconds) }
            else {
                let formatter = DateFormatter()
                formatter.locale = Locale(identifier: "en_US_POSIX")
                formatter.timeZone = TimeZone(secondsFromGMT: 0)
                formatter.dateFormat = "EEE',' dd MMM yyyy HH':'mm':'ss z"
                if let date = formatter.date(from: raw) { delay = max(delay, date.timeIntervalSince(now)) }
            }
        }
        // Cloudflare Ratelimit header includes the window's remaining seconds (t).
        if let header = reset {
            for item in header.split(separator: ";") {
                let part = item.trimmingCharacters(in: .whitespaces)
                if part.hasPrefix("t="), let seconds = Double(part.dropFirst(2)), seconds.isFinite {
                    delay = max(delay, seconds + 5)
                }
            }
        }
        return min(21630, delay)
    }
}
