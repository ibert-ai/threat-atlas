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
}

/// Owns the shared OSINT worker. A source that is switched off makes no request at all; the worker
/// itself checks the switch before every request.
final class OsintController: ObservableObject {
    static let shared = OsintController()
    private static let defaultsKey = "atlassoc.enabledSources"

    @Published private(set) var sources: [OsintSource] = []
    @Published private(set) var enabled: Set<String> = []
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
    }

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
