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
    /// Whether a token is saved, from its attributes only: the secret is not decrypted, so no
    /// Keychain access prompt can block launch (each ad-hoc build is a new code identity).
    static func exists() -> Bool {
        var q = query; q[kSecReturnAttributes as String] = true
        var value: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &value) == errSecSuccess
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
@MainActor final class RadarModel: ObservableObject {
    @Published var result: RadarResult?
    @Published var message = "No data yet. Add a Cloudflare Radar Read token."
    @Published var busy = false
    @Published var enabled = false
    @Published var next: Date
    @Published var received: Date?
    /// A token is saved in Keychain (its value is never kept here).
    @Published var hasToken = false
    /// The saved token last got HTTP 200 from Cloudflare; persisted, cleared on 401/403 or a new token.
    @Published var tokenVerified: Bool { didSet { defaults.set(tokenVerified, forKey: "radar.tokenVerified") } }
    /// The user left polling on; the app resumes it on the next launch when the token is verified.
    private var keepPolling: Bool { didSet { defaults.set(keepPolling, forKey: "radar.keepPolling") } }
    /// Token saved and known to work: the window hides the token setup and shows a compact status bar.
    var configured: Bool { hasToken && tokenVerified }
    private var failures = 0
    private let defaults: UserDefaults
    private let delegate = NoRedirect()
    private let directory: URL
    private let readToken: () -> String?
    private let saveToken: (String) -> Bool
    private var lockFD: Int32 = -1
    private var session: URLSession!
    private var running = false
    /// Defaults are the app's real locations. Tests pass a temporary directory, a private defaults
    /// suite, a fixed token, a token saver that never touches Keychain and a stub protocol that
    /// replaces all networking.
    init(directory customDirectory: URL? = nil, defaults: UserDefaults = .standard,
         token: @escaping () -> String? = TokenStore.read, tokenExists: (() -> Bool)? = nil, saveToken: @escaping (String) -> Bool = TokenStore.save,
         protocolClasses: [AnyClass]? = nil) {
        self.defaults = defaults
        readToken = token
        self.saveToken = saveToken
        tokenVerified = defaults.bool(forKey: "radar.tokenVerified")
        keepPolling = defaults.bool(forKey: "radar.keepPolling")
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
        hasToken = (tokenExists ?? TokenStore.exists)()
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
    func save(token: String) {
        let clean = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty, clean.count < 4096, !clean.contains("\n"), !clean.contains("\r") else {
            message = "Enter a valid Radar Read token."; return
        }
        if saveToken(clean) {
            hasToken = true; tokenVerified = false
            message = "Token saved in Keychain. Press Start when ready."
        } else {
            message = "Keychain save failed. No request sent."
        }
    }
    /// Resume polling at launch only if the user left it on and the saved token is known to work.
    func resumeIfConfigured() { if configured && keepPolling && !enabled { start() } }
    func setNext(_ date: Date) { next = date; defaults.set(date.timeIntervalSince1970, forKey: "nextRequest") }
    func start() { guard running else { return }; enabled = true; keepPolling = true; Task { await refresh() } }
    func stop() { enabled = false; keepPolling = false; message = "Paused. Saved data remains visible." }
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
                enabled = false; tokenVerified = false; message = "Authorization denied (\(http.statusCode)). Polling stopped; verify Radar Read permission."; return
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
            result = parsed; received = Date(); failures = 0; tokenVerified = true
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
