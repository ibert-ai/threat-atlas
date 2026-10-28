import Foundation
import Security

// Runs outside the screen saver host, at user privilege, only after explicit opt-in.
enum UpdateError: Error { case invalid(String) }
let fm = FileManager.default
let home = fm.homeDirectoryForCurrentUser
let appName = "Threat Atlas SOC.app"
let app = home.appendingPathComponent("Applications/\(appName)")
let saver = home.appendingPathComponent("Library/Screen Savers/ThreatAtlasSOC.saver")
let agent = home.appendingPathComponent("Library/LaunchAgents/dev.threatatlas.updater.plist")
let status = home.appendingPathComponent("Library/Logs/ThreatAtlas-update.log")
let uid = getuid()
func run(_ path: String, _ args: [String]) throws {
    let process = Process(); process.executableURL = URL(fileURLWithPath: path); process.arguments = args
    try process.run(); process.waitUntilExit()
    guard process.terminationStatus == 0 else { throw UpdateError.invalid("Command failed: \(path)") }
}
func signedTeam(_ path: URL, identifier: String? = nil, team: String? = nil) throws -> String {
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(path as CFURL, [], &code) == errSecSuccess, let code = code else { throw UpdateError.invalid("Missing signed code") }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let values = info as? [String: Any], let found = values[kSecCodeInfoTeamIdentifier as String] as? String,
          found.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil else { throw UpdateError.invalid("Developer ID signing is required; ad-hoc previews cannot auto-update") }
    let wanted = team ?? found
    var requirement: SecRequirement?
    var rule = "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"\(wanted)\""
    if let identifier = identifier { rule += " and identifier \"\(identifier)\"" }
    guard SecRequirementCreateWithString(rule as CFString, [], &requirement) == errSecSuccess,
          SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSCheckNestedCode | kSecCSStrictValidate), requirement) == errSecSuccess else { throw UpdateError.invalid("Update signature/publisher verification failed") }
    return found
}
func output(_ path: String, _ args: [String]) throws -> String {
    let process = Process(); let pipe = Pipe(); process.executableURL = URL(fileURLWithPath: path); process.arguments = args; process.standardOutput = pipe
    try process.run(); let data = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
    guard process.terminationStatus == 0, let text = String(data: data, encoding: .utf8) else { throw UpdateError.invalid("Archive inspection failed") }; return text
}
func inspectArchive(_ archive: URL) throws {
    let paths = try output("/usr/bin/unzip", ["-Z1", archive.path]).split(separator: "\n")
    guard !paths.isEmpty, paths.count < 10000 else { throw UpdateError.invalid("Invalid archive entries") }
    for entry in paths {
        let path = String(entry); let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !path.hasPrefix("/"), !path.contains("\\"), !parts.contains(".."), !parts.contains("."),
              parts.first == "ThreatAtlasSOC.saver" || parts.first == "Threat Atlas SOC.app" else { throw UpdateError.invalid("Unsafe archive path") }
    }
    let listing = try output("/usr/bin/zipinfo", ["-l", archive.path])
    var total: Int64 = 0
    var entries = 0
    for line in listing.split(separator: "\n") where line.first == "-" || line.first == "l" || line.first == "d" || line.first == "?" {
        let fields = line.split(whereSeparator: { $0.isWhitespace })
        guard line.first != "l", fields.count >= 4, let size = Int64(fields[3]), size >= 0, size <= 300_000_000 - total else { throw UpdateError.invalid("Archive links or excessive expansion rejected") }; total += size; entries += 1
    }
    guard entries == paths.count else { throw UpdateError.invalid("Unrecognized archive entries") }
}
func version(_ text: String) throws -> [Int] {
    guard text.range(of: "^v?[0-9]+\\.[0-9]+\\.[0-9]+$", options: .regularExpression) != nil else { throw UpdateError.invalid("Not a stable version") }
    let parts = text.replacingOccurrences(of: "v", with: "").split(separator: ".").compactMap { Int($0) }
    guard parts.count == 3 else { throw UpdateError.invalid("Version overflow") }; return parts
}
func bundleVersion(_ url: URL) throws -> String {
    guard let value = Bundle(url: url)?.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String else { throw UpdateError.invalid("Missing bundle version") }; return value
}
struct Asset: Decodable { let name: String; let size: Int; let browser_download_url: URL }
struct Release: Decodable { let tag_name: String; let draft: Bool; let prerelease: Bool; let assets: [Asset] }
func download(_ url: URL, to file: URL, limit: Int) throws {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.timeoutIntervalForRequest = 30; configuration.timeoutIntervalForResource = 120
    let session = URLSession(configuration: configuration); defer { session.invalidateAndCancel() }
    let finished = DispatchSemaphore(value: 0)
    final class Outcome: @unchecked Sendable { var value: Result<Void, Error>? }
    let outcome = Outcome()
    var request = URLRequest(url: url); request.setValue("ThreatAtlas-Updater", forHTTPHeaderField: "User-Agent")
    session.downloadTask(with: request) { temporary, response, error in
        defer { finished.signal() }
        do {
            if let error = error { throw error }
            guard let temporary = temporary, let response = response as? HTTPURLResponse,
                  response.statusCode == 200, response.url?.scheme == "https",
                  (try fm.attributesOfItem(atPath: temporary.path)[.size] as? NSNumber)?.intValue ?? Int.max <= limit else { throw UpdateError.invalid("Invalid/oversized download") }
            try fm.moveItem(at: temporary, to: file); outcome.value = .success(())
        } catch { outcome.value = .failure(error) }
    }.resume()
    finished.wait()
    guard let result = outcome.value else { throw UpdateError.invalid("Download did not complete") }; try result.get()
}
func log(_ message: String) { try? fm.createDirectory(at: status.deletingLastPathComponent(), withIntermediateDirectories: true); try? "\(Date()): \(message)\n".write(to: status, atomically: true, encoding: .utf8) }
func saverIsBusy() throws -> Bool {
    for name in ["ScreenSaverEngine", "legacyScreenSaver", "legacyScreenSaver-x86_64", "ThreatAtlasPreview", "System Settings", "System Preferences"] {
        let check = Process(); check.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep"); check.arguments = ["-x", name]; check.standardOutput = FileHandle.nullDevice
        try check.run(); check.waitUntilExit(); if check.terminationStatus == 0 { return true }
    }
    return false
}
func main() throws {
    let mode = CommandLine.arguments.dropFirst().first ?? "--check"
    if mode == "--inspect-archive", CommandLine.arguments.count == 3 {
        try inspectArchive(URL(fileURLWithPath: CommandLine.arguments[2])); return
    }
    if mode == "--self-test" {
        guard try version("v1.2.3") == [1,2,3], try version("1.10.0").lexicographicallyPrecedes(version("2.0.0")) else { throw UpdateError.invalid("Version test failed") }
        for invalid in ["v1.0.0-rc.1", "1.2", "../1.0.0", "1.0.0.1"] {
            do { _ = try version(invalid); throw UpdateError.invalid("Accepted invalid version") } catch UpdateError.invalid(let message) where message == "Not a stable version" { }
        }
        print("Updater version tests passed"); return
    }
    if mode == "--disable" {
        try? run("/bin/launchctl", ["bootout", "gui/\(uid)", agent.path]); try? fm.removeItem(at: agent); log("Automatic updates disabled"); return
    }
    guard mode == "--check" || mode == "--enable" else { throw UpdateError.invalid("Unknown mode") }
    let executable = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
    let sourceApp = executable.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let team = try signedTeam(sourceApp, identifier: "dev.threatatlas.preview.v4")
    _ = try signedTeam(saver, identifier: "dev.threatatlas.soc.screensaver", team: team)
    if mode == "--enable" {
        if sourceApp != app {
            try fm.createDirectory(at: app.deletingLastPathComponent(), withIntermediateDirectories: true)
            guard !fm.fileExists(atPath: app.path) else { throw UpdateError.invalid("Use the preview in ~/Applications to enable updates, or remove its older copy first") }
            try fm.copyItem(at: sourceApp, to: app)
        }
        let plist: [String: Any] = ["Label": "dev.threatatlas.updater", "ProgramArguments": [app.appendingPathComponent("Contents/MacOS/ThreatAtlasUpdater").path, "--check"], "StartInterval": 86400, "RunAtLoad": true, "ProcessType": "Background"]
        try fm.createDirectory(at: agent.deletingLastPathComponent(), withIntermediateDirectories: true)
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try? run("/bin/launchctl", ["bootout", "gui/\(uid)", agent.path])
        try data.write(to: agent, options: .atomic)
        try run("/bin/launchctl", ["bootstrap", "gui/\(uid)", agent.path]); log("Automatic updates enabled"); return
    }
    if try saverIsBusy() { log("Update deferred while screen saver/settings/preview is running"); return }
    let stage = fm.temporaryDirectory.appendingPathComponent("ThreatAtlas-update-\(UUID().uuidString)")
    try fm.createDirectory(at: stage, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]); defer { try? fm.removeItem(at: stage) }
    let metadata = stage.appendingPathComponent("release.json")
    try download(URL(string: "https://api.github.com/repos/ibert-ai/threat-atlas/releases/latest")!, to: metadata, limit: 2_000_000)
    let release = try JSONDecoder().decode(Release.self, from: Data(contentsOf: metadata))
    guard !release.draft, !release.prerelease else { throw UpdateError.invalid("Only stable releases accepted") }
    let next = try version(release.tag_name), current = try version(bundleVersion(saver))
    guard current.lexicographicallyPrecedes(next) else { log("Already up to date"); return }
    let matches = release.assets.filter { $0.name == "ThreatAtlas-macOS.zip" }
    guard matches.count == 1, let asset = matches.first, asset.size > 0, asset.size <= 100_000_000,
          asset.browser_download_url.scheme == "https", asset.browser_download_url.host == "github.com",
          asset.browser_download_url.path.hasPrefix("/ibert-ai/threat-atlas/releases/download/") else { throw UpdateError.invalid("Missing stable macOS update asset") }
    let archive = stage.appendingPathComponent("update.zip")
    try download(asset.browser_download_url, to: archive, limit: 100_000_000)
    try inspectArchive(archive)
    let unpacked = stage.appendingPathComponent("unpacked")
    try run("/usr/bin/ditto", ["-xk", archive.path, unpacked.path])
    let newApp = unpacked.appendingPathComponent(appName), newSaver = unpacked.appendingPathComponent("ThreatAtlasSOC.saver")
    _ = try signedTeam(newApp, identifier: "dev.threatatlas.preview.v4", team: team)
    _ = try signedTeam(newSaver, identifier: "dev.threatatlas.soc.screensaver", team: team)
    guard try version(bundleVersion(newApp)) == next, try version(bundleVersion(newSaver)) == next else { throw UpdateError.invalid("Release and bundle versions differ") }
    try run("/usr/sbin/spctl", ["--assess", "--type", "execute", newApp.path])
    if try saverIsBusy() { log("Update deferred: screen saver/settings/preview started during download"); return }
    // Stage on each destination volume, then rename with rollback on failure.
    let pairs = [(newSaver, saver), (newApp, app)]
    var backups: [(URL, URL)] = []
    do {
        for (source, destination) in pairs {
            let pending = destination.deletingLastPathComponent().appendingPathComponent(".ThreatAtlas-new-\(UUID().uuidString)")
            try fm.copyItem(at: source, to: pending); defer { try? fm.removeItem(at: pending) }
            let backup = destination.deletingLastPathComponent().appendingPathComponent(".ThreatAtlas-old-\(UUID().uuidString)")
            try fm.moveItem(at: destination, to: backup); backups.append((destination, backup))
            try fm.moveItem(at: pending, to: destination)
        }
    } catch {
        for (destination, backup) in backups.reversed() { try? fm.removeItem(at: destination); try? fm.moveItem(at: backup, to: destination) }; throw error
    }
    for (_, backup) in backups { try? fm.removeItem(at: backup) }
    log("Updated to \(release.tag_name); active on next screen saver launch")
}
do { try main(); exit(0) } catch { if !CommandLine.arguments.contains("--inspect-archive") && !CommandLine.arguments.contains("--self-test") { log("Update stopped: \(error)") }; fputs("\(error)\n", stderr); exit(1) }
