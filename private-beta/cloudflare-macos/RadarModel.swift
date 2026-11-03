import Foundation
import Security
import Darwin

// Request worker for the private Radar beta, moved out of RadarApp.swift so offline lifecycle tests
// can inject a temporary directory, defaults suite, token source and URL protocol stub.

final class NoRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
enum TokenStore {
    static let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "ThreatAtlas.PrivateRadarBeta", kSecAttrAccount as String: "RadarRead"]
    static func read() -> String? {
        var q = query; q[kSecReturnData as String] = true
        var value: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &value) == errSecSuccess,
              let data = value as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
    static func save(_ token: String) -> Bool {
        let values = [kSecValueData as String: Data(token.utf8)]
        let result = SecItemUpdate(query as CFDictionary, values as CFDictionary)
        if result == errSecItemNotFound {
            var q = query; q.merge(values) { _, new in new }
            q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            return SecItemAdd(q as CFDictionary, nil) == errSecSuccess
        }
        return result == errSecSuccess
    }
}
/// One visible worker state, so licence acceptance, the token and collection never look like separate
/// hidden steps (SOC-DATA-001).
enum RadarStatus: Equatable {
    case otherWorker, needsToken, denied, paused, waiting(Date), fetching, current, stale, unavailable
}
@MainActor final class RadarModel: ObservableObject {
    @Published var result: RadarResult?
    @Published var message = "No data yet. Add a Cloudflare Radar Read token."
    @Published var busy = false
    @Published var enabled = false
    @Published var next: Date
    @Published var received: Date?
    @Published private(set) var hasToken = false
    private var failures = 0
    private let defaults: UserDefaults
    private let delegate = NoRedirect()
    private let directory: URL
    private let readToken: () -> String?
    private let storeToken: (String) -> Bool
    /// Persisted user choices: Pause survives relaunch; an authorization failure is not retried
    /// automatically until a new token is saved.
    private static let pausedKey = "radarPaused", deniedKey = "radarDenied"
    private var lockFD: Int32 = -1
    private var session: URLSession!
    private var running = false
    /// Defaults are the app's real locations. Tests pass a temporary directory, a private defaults
    /// suite, a fixed token and a stub protocol that replaces all networking.
    init(directory customDirectory: URL? = nil, defaults: UserDefaults = .standard,
         token: @escaping () -> String? = TokenStore.read, saveToken: @escaping (String) -> Bool = TokenStore.save,
         protocolClasses: [AnyClass]? = nil) {
        self.defaults = defaults
        readToken = token
        storeToken = saveToken
        next = Date(timeIntervalSince1970: defaults.double(forKey: "nextRequest"))
        directory = customDirectory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("ThreatAtlasPrivateRadar", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                  attributes: [.posixPermissions: 0o700])
        lockFD = open(directory.appendingPathComponent("worker.lock").path, O_CREAT | O_RDWR, 0o600)
        guard lockFD >= 0, flock(lockFD, LOCK_EX | LOCK_NB) == 0 else {
            message = "Another private Radar beta worker is running. Use its window."; return
        }
        running = true
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil; config.httpShouldSetCookies = false
        config.urlCache = nil; config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 20; config.timeoutIntervalForResource = 30
        config.httpMaximumConnectionsPerHost = 1
        if let protocolClasses { config.protocolClasses = protocolClasses }
        session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
        if let data = try? Data(contentsOf: directory.appendingPathComponent("snapshot.json")),
           let cache = try? JSONDecoder().decode(Snapshot.self, from: data) {
            result = cache.result; received = cache.received
            message = "Saved aggregate data. Not live individual events."
        }
    }
    struct Snapshot: Codable { let result: RadarResult; let received: Date }
    var status: RadarStatus {
        if !running { return .otherWorker }
        if busy { return .fetching }
        if defaults.bool(forKey: Self.deniedKey) { return .denied }
        if !hasToken { return .needsToken }
        if !enabled { return .paused }
        if let received { return Date().timeIntervalSince(received) > 1800 ? .stale : .current }
        if failures > 0 { return .unavailable }
        return .waiting(max(next, Date()))
    }
    /// Called once the licence gate has been passed. Starts (or resumes) collection when a token is
    /// already saved, unless the user paused it or the token was refused; `refresh` still enforces
    /// the persisted 15-minute interval, so relaunch never adds a request.
    func autoStart(consented: Bool) {
        guard consented, running else { return }
        hasToken = !(readToken() ?? "").isEmpty
        if !hasToken { message = "Add a Cloudflare Radar Read token to show Radar data. GreyNoise live data needs no token."; return }
        if defaults.bool(forKey: Self.deniedKey) { message = "Cloudflare refused the saved token. Save a token with Radar Read permission."; return }
        if defaults.bool(forKey: Self.pausedKey) { message = "Radar collection is paused. Press Start to resume."; return }
        resume()
    }
    func save(token: String) {
        let clean = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty, clean.count < 4096, !clean.contains("\n"), !clean.contains("\r") else {
            message = "Enter a valid Radar Read token."; return
        }
        guard storeToken(clean) else { message = "Keychain save failed. No request sent."; return }
        // A newly saved token is the user's go-ahead: no second Start step.
        hasToken = true
        defaults.removeObject(forKey: Self.deniedKey); defaults.removeObject(forKey: Self.pausedKey)
        resume()
    }
    func setNext(_ date: Date) { next = date; defaults.set(date.timeIntervalSince1970, forKey: "nextRequest") }
    func start() { guard running else { return }; defaults.removeObject(forKey: Self.pausedKey); resume() }
    func stop() { enabled = false; defaults.set(true, forKey: Self.pausedKey); message = "Paused. Saved data remains visible." }
    private func resume() {
        guard running else { return }
        enabled = true
        if Date() < next {
            message = "Token saved. Next Cloudflare request \(next.formatted(date: .omitted, time: .shortened)) (at most once per 15 minutes)."
        }
        Task { await refresh() }
    }
    func refresh() async {
        guard running, enabled, !busy, Date() >= next else { return }
        guard let token = readToken(), !token.isEmpty else {
            enabled = false; hasToken = false; message = "Radar Read token required. No request sent."; return
        }
        busy = true
        defer { busy = false }
        // Persist the minimum interval BEFORE I/O: relaunch, sleep/wake and manual refresh cannot bypass it.
        setNext(Date().addingTimeInterval(PollPolicy.interval))
        var request = URLRequest(url: URL(string: "https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/attacks?dateRange=1d&limit=20&format=JSON")!)
        request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("ThreatAtlas-PrivateRadarBeta/0.1", forHTTPHeaderField: "User-Agent")
        message = "Fetching Cloudflare Radar aggregate data…"
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else { throw RadarError.invalidResponse }
            if http.statusCode == 401 || http.statusCode == 403 {
                enabled = false; defaults.set(true, forKey: Self.deniedKey)
                message = "Authorization denied (\(http.statusCode)). Polling stopped; save a token with Radar Read permission."; return
            }
            guard http.statusCode == 200 else {
                failures += 1
                setNext(Date().addingTimeInterval(PollPolicy.delay(status: http.statusCode,
                    retryAfter: http.value(forHTTPHeaderField: "Retry-After"),
                    reset: http.value(forHTTPHeaderField: "Ratelimit"), failures: failures, now: Date())))
                if (300..<500).contains(http.statusCode) && http.statusCode != 429 { enabled = false }
                message = "HTTP \(http.statusCode). Saved data retained; cooldown applies.\(!enabled ? " Polling stopped." : "")"; return
            }
            let parsed = try parseRadar(data)
            result = parsed; received = Date(); failures = 0
            if let remaining = http.value(forHTTPHeaderField: "Ratelimit"), remaining.contains("r=0") {
                setNext(Date().addingTimeInterval(PollPolicy.delay(status: 200, retryAfter: nil,
                    reset: remaining, failures: 0, now: Date())))
            }
            let cache = try JSONEncoder().encode(Snapshot(result: parsed, received: received!))
            try cache.write(to: directory.appendingPathComponent("snapshot.json"), options: .atomic)
            message = "Cloudflare Radar · aggregated network-layer attack origins · past day"
        } catch {
            failures += 1
            setNext(Date().addingTimeInterval(PollPolicy.delay(status: 0, retryAfter: nil, reset: nil,
                failures: failures, now: Date())))
            message = "Fetch or response validation failed. Saved data retained; retry after cooldown."
        }
    }
}
