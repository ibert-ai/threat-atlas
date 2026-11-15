import Foundation
import AppKit

/// One data source as described by the shared core.
struct OsintSource: Identifiable, Decodable, Equatable {
    let id: String
    let name: String
    let licence: String
    let attribution: String
    let min_minutes: Int
    let requires_key: Bool
    let default_on: Bool
    /// True for sources that act on an address or domain the user copied.
    let clipboard: Bool
    /// One sentence: what this source tells you.
    let what: String
}

/// The user'"'"'s own API keys, kept in the macOS Keychain (never in a file, preference or log).
enum OsintKeys {
    private static let service = "ThreatAtlas.OSINT"
    /// Keychain account name per source id. Several sources of one provider share a key.
    static func account(_ id: String) -> String {
        switch id {
        case "alienvault-otx": return "otx"
        case "threatfox", "urlhaus": return "abusech"
        case "abuseipdb": return "abuseipdb"
        case "cert-spotter": return "certspotter"
        default: return id
        }
    }
    private static func query(_ id: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: account(id)]
    }
    static func read(_ id: String) -> String? {
        var q = query(id)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &value) == errSecSuccess,
              let data = value as? Data, let key = String(data: data, encoding: .utf8) else { return nil }
        return key.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    static func exists(_ id: String) -> Bool {
        var q = query(id)
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        return SecItemCopyMatching(q as CFDictionary, nil) == errSecSuccess
    }
    @discardableResult static func save(_ id: String, key: String) -> Bool {
        let data = Data(key.trimmingCharacters(in: .whitespacesAndNewlines).utf8)
        let status = SecItemUpdate(query(id) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var q = query(id)
            q[kSecValueData as String] = data
            return SecItemAdd(q as CFDictionary, nil) == errSecSuccess
        }
        return status == errSecSuccess
    }
    static func remove(_ id: String) { SecItemDelete(query(id) as CFDictionary) }
}

/// Owns the shared OSINT worker. A source that is switched off makes no request at all; the worker
/// itself checks the switch before every request.
final class OsintController: ObservableObject {
    static let shared = OsintController()
    private static let defaultsKey = "atlassoc.enabledSources"

    @Published private(set) var sources: [OsintSource] = []
    @Published private(set) var enabled: Set<String> = []
    /// Bumped by a timer so the status lines in Settings stay current.
    @Published private(set) var tick = 0
    /// Which keyed sources currently have a key in the Keychain (the key itself is never published).
    @Published private(set) var keyed: Set<String> = []
    private var timer: Timer?
    private var handle: UnsafeMutableRawPointer?

    private init() {
        sources = Self.loadSources()
        if let saved = UserDefaults.standard.array(forKey: Self.defaultsKey) as? [String] {
            let known = Set(sources.map(\.id))
            enabled = Set(saved).intersection(known)
        } else {
            enabled = Set(sources.filter(\.default_on).map(\.id))
        }
    }

    private static func loadSources() -> [OsintSource] {
        let needed = ta_osint_sources(nil, 0)
        var buffer = [UInt8](repeating: 0, count: needed)
        let written = ta_osint_sources(&buffer, needed)
        guard written == needed,
              let list = try? JSONDecoder().decode([OsintSource].self, from: Data(buffer)) else { return [] }
        return list
    }

    private func json() -> String {
        let data = (try? JSONSerialization.data(withJSONObject: enabled.sorted())) ?? Data("[]".utf8)
        return String(decoding: data, as: UTF8.self)
    }

    /// Starts the worker. Call only after the licence was accepted (the app's consent gate).
    func start() {
        guard handle == nil else { return }
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("ThreatAtlasPrivateRadar/osint", isDirectory: true)
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        handle = ta_osint_start(base.path, json())
        pushKeys()
    }

    /// Hands every stored key to the worker, which keeps it in memory only.
    func pushKeys() {
        var have: Set<String> = []
        for source in sources where source.requires_key {
            guard let key = OsintKeys.read(source.id) else { continue }
            have.insert(source.id)
            if let handle { _ = ta_osint_set_key(handle, source.id, key) }
        }
        keyed = have
    }

    func setKey(_ id: String, _ key: String) {
        guard OsintKeys.save(id, key: key) else { return }
        pushKeys()
    }

    func removeKey(_ id: String) {
        OsintKeys.remove(id)
        if let handle { _ = ta_osint_set_key(handle, id, nil) }
        keyed.remove(id)
    }

    func startTicking() {
        guard timer == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in self?.tick += 1 }
    }

    func stopTicking() { timer?.invalidate(); timer = nil }

    /// One line: what has arrived and when. Empty text when the source is off.
    func status(_ source: OsintSource) -> String {
        guard isOn(source.id) else { return "Off: no requests are made." }
        guard let handle else { return "Starting..." }
        let needed = ta_osint_status(handle, source.id, nil, 0)
        guard needed > 0 else { return "" }
        var buffer = [UInt8](repeating: 0, count: needed)
        let written = ta_osint_status(handle, source.id, &buffer, needed)
        return String(decoding: buffer.prefix(min(written, needed)), as: UTF8.self)
    }

    /// The worker handle for the C interface (nil until `start`).
    var rawHandle: UnsafeMutableRawPointer? { handle }

    func isOn(_ id: String) -> Bool { enabled.contains(id) }

    func set(_ id: String, on: Bool) {
        if on { enabled.insert(id) } else { enabled.remove(id) }
        UserDefaults.standard.set(enabled.sorted(), forKey: Self.defaultsKey)
        if let handle { ta_osint_set_enabled(handle, json()) }
    }

    func refresh() { if let handle { ta_osint_refresh(handle) } }

    static func clipboardText() -> String {
        String((NSPasteboard.general.string(forType: .string) ?? "").prefix(300))
    }

    /// Text page for one source. Reads the clipboard only for the sources that check a copied item.
    func page(_ source: OsintSource) -> String {
        guard isOn(source.id) else {
            return "\(source.name) is turned off, so it makes no requests. Turn it on in Settings."
        }
        guard let handle else { return "The data worker has not started yet." }
        let clip = source.clipboard ? Self.clipboardText() : ""
        let needed = ta_osint_page(handle, source.id, clip, nil, 0)
        guard needed > 0 else { return "No data." }
        var buffer = [UInt8](repeating: 0, count: needed)
        let written = ta_osint_page(handle, source.id, clip, &buffer, needed)
        return String(decoding: buffer.prefix(min(written, needed)), as: UTF8.self)
    }

    /// Queues the click-only InternetDB lookup. Returns false when refused.
    func lookup(_ ip: String) -> Bool {
        guard let handle, isOn("shodan-internetdb") else { return false }
        return ta_osint_lookup(handle, ip) == 0
    }

    deinit { if let handle { ta_osint_drop(handle) } }
}
