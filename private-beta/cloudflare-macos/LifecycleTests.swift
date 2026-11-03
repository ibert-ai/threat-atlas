import Foundation
// Offline request-policy lifecycle tests for RadarModel. StubProtocol replaces every URL protocol in the
// worker's session, so nothing reaches the network. Each model uses a temporary directory, a private
// defaults suite and a fixed fake token: no Keychain, no real app data, no Cloudflare request.
// Run: xcrun swiftc -parse-as-library RadarCore.swift RadarModel.swift LicenseConsent.swift LifecycleTests.swift -o /private/tmp/radar-lifecycle-tests && /private/tmp/radar-lifecycle-tests

enum Stub { case http(Int, [String: String], Data); case failure(URLError) }
final class StubProtocol: URLProtocol {
    nonisolated(unsafe) static var queue: [Stub] = []
    nonisolated(unsafe) static var hosts: [String] = []
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.hosts.append(request.url?.host ?? "")
        let stub = Self.queue.isEmpty ? Stub.failure(URLError(.notConnectedToInternet)) : Self.queue.removeFirst()
        switch stub {
        case let .http(code, headers, body):
            let response = HTTPURLResponse(url: request.url!, statusCode: code, httpVersion: "HTTP/1.1", headerFields: headers)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: body)
            client?.urlProtocolDidFinishLoading(self)
        case let .failure(error): client?.urlProtocol(self, didFailWithError: error)
        }
    }
    override func stopLoading() {}
}

// Synthetic fixture only: never presented as telemetry.
let validBody = Data(#"{"success":true,"result":{"meta":{"lastUpdated":"2026-01-01T00:00:00Z","normalization":"PERCENTAGE","dateRange":[{"startTime":"2025-12-31T00:00:00Z","endTime":"2026-01-01T00:00:00Z"}]},"top_0":[{"originCountryAlpha2":"FR","originCountryName":"France","value":"4.3"}]}}"#.utf8)

@MainActor final class Harness {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("radar-lifecycle-" + UUID().uuidString)
    var suites: [String] = []
    func defaults() -> UserDefaults {
        let name = "ThreatAtlasRadarLifecycleTests." + UUID().uuidString
        suites.append(name); return UserDefaults(suiteName: name)!
    }
    func model(_ dir: String, defaults: UserDefaults? = nil, token: String? = "fake-test-token") -> RadarModel {
        model(dir, defaults: defaults, token: { token })
    }
    /// Variant with a changeable token source; saving goes to `saved`, never to the Keychain.
    func model(_ dir: String, defaults: UserDefaults? = nil, token: @escaping () -> String?,
               saved: @escaping (String) -> Bool = { _ in true }) -> RadarModel {
        RadarModel(directory: root.appendingPathComponent(dir, isDirectory: true), defaults: defaults ?? self.defaults(),
                   token: token, saveToken: saved, protocolClasses: [StubProtocol.self])
    }
    /// Runs one startup path (which starts its own refresh task) and returns the requests it made.
    func requests(_ stubs: [Stub], _ action: () -> Void) async -> Int {
        StubProtocol.queue = stubs; let before = StubProtocol.hosts.count
        action()
        try? await Task.sleep(nanoseconds: 300_000_000)
        for _ in 0..<50 { if StubProtocol.hosts.count == before || !busyModels() { break }; try? await Task.sleep(nanoseconds: 100_000_000) }
        StubProtocol.queue = []
        return StubProtocol.hosts.count - before
    }
    var watched: [RadarModel] = []
    func busyModels() -> Bool { watched.contains { $0.busy } }
    /// One eligible poll: clears the persisted interval, enables polling and returns the requests it made.
    func poll(_ m: RadarModel, _ stubs: [Stub]) async -> Int {
        StubProtocol.queue = stubs; let before = StubProtocol.hosts.count
        m.setNext(.distantPast); m.enabled = true
        await m.refresh()
        return StubProtocol.hosts.count - before
    }
    func cleanup() {
        suites.forEach { UserDefaults.standard.removePersistentDomain(forName: $0) }
        try? FileManager.default.removeItem(at: root)
    }
}
func check(_ ok: Bool, _ what: String) { precondition(ok, what); print("ok  " + what) }

@main struct LifecycleTests {
    @MainActor static func main() async {
        let h = Harness()
        defer { h.cleanup() }

        // Single worker: a second model on the same directory cannot take the lock and never requests.
        let first = h.model("single")
        let second = h.model("single")
        check(second.message.contains("Another private Radar beta worker"), "second worker on same directory is refused")
        check(await h.poll(second, [.http(200, [:], validBody)]) == 0, "refused worker makes no request")
        _ = first

        // Missing token: stops before any request.
        let noToken = h.model("notoken", token: nil)
        check(await h.poll(noToken, []) == 0 && !noToken.enabled, "missing token stops polling with no request")

        // Authorization stop: 401 and 403 disable polling; later timer ticks make no request.
        for code in [401, 403] {
            let m = h.model("auth\(code)")
            check(await h.poll(m, [.http(code, [:], Data())]) == 1, "\(code): one request made")
            check(!m.enabled && m.message.contains("\(code)"), "\(code): polling stopped with visible reason")
            let count = StubProtocol.hosts.count
            StubProtocol.queue = [.http(200, [:], validBody)]
            m.setNext(.distantPast); await m.refresh()
            check(StubProtocol.hosts.count == count && !m.enabled, "\(code): later timer tick makes no request")
            StubProtocol.queue = []
        }

        // Permanent client error stops; 429 keeps polling but honours Retry-After.
        let notFound = h.model("404")
        _ = await h.poll(notFound, [.http(404, [:], Data())])
        check(!notFound.enabled, "404: permanent client error stops polling")
        let limited = h.model("429")
        _ = await h.poll(limited, [.http(429, ["Retry-After": "3600"], Data())])
        check(limited.enabled && limited.next.timeIntervalSinceNow > 3590, "429: polling kept, next request after Retry-After 3600 s")

        // Quota reset: a successful response with no remaining quota waits for the window reset.
        let quota = h.model("quota")
        _ = await h.poll(quota, [.http(200, ["Ratelimit": "\"default\";r=0;t=2000"], validBody)])
        check(quota.result != nil && quota.next.timeIntervalSinceNow > 1990, "quota r=0: data kept, next request after reset window (2005 s)")

        // Failure and recovery: saved data survives HTTP, network and validation failures, then refreshes.
        let m = h.model("recovery")
        _ = await h.poll(m, [.http(200, [:], validBody)])
        let firstReceipt = m.received
        check(m.result?.top_0.first?.value == "4.3" && firstReceipt != nil, "initial success stored")
        check(FileManager.default.fileExists(atPath: h.root.appendingPathComponent("recovery/snapshot.json").path), "snapshot persisted")
        _ = await h.poll(m, [.http(500, [:], Data())])
        check(m.enabled && m.result != nil && m.received == firstReceipt && m.next.timeIntervalSinceNow >= 899, "500: data and receipt time retained, cooldown at least 15 min")
        _ = await h.poll(m, [.failure(URLError(.timedOut))])
        check(m.result != nil && m.message.contains("failed"), "network timeout: data retained, failure shown")
        _ = await h.poll(m, [.http(200, [:], Data("{not json".utf8))])
        check(m.result != nil && m.received == firstReceipt, "invalid payload: rejected, previous data kept")
        _ = await h.poll(m, [.http(200, [:], validBody)])
        check(m.received != firstReceipt && m.message.hasPrefix("Cloudflare Radar"), "recovery: fresh data accepted")
        _ = await h.poll(m, [.http(500, [:], Data())])
        check(m.next.timeIntervalSinceNow < 950, "recovery reset the failure count (backoff back to base)")

        // Sleep/wake and relaunch: after a request the persisted interval blocks catch-up bursts.
        let d = h.defaults()
        let awake = h.model("wake", defaults: d)
        _ = await h.poll(awake, [.http(200, [:], validBody)])
        let before = StubProtocol.hosts.count
        StubProtocol.queue = Array(repeating: .http(200, [:], validBody), count: 5)
        for _ in 0..<5 { await awake.refresh() }   // simulated timer ticks after wake
        check(StubProtocol.hosts.count == before, "wake burst: 5 timer ticks inside the interval make no request")
        let relaunched = h.model("wake-relaunch", defaults: d)
        relaunched.enabled = true; await relaunched.refresh()
        check(StubProtocol.hosts.count == before, "relaunch: persisted next-request time is honoured")
        StubProtocol.queue = []

        // SOC-DATA-001 startup flow: licence acceptance plus a saved token is enough; no hidden Start step.
        let terms = LicenseTerms(version: "0.7.0", build: "11", notice: "Synthetic notice.", noticeSHA256: "aaa",
                                 legalSHA256: "bbb", noticeURL: URL(string: "https://example.invalid/n")!,
                                 licenseURL: URL(string: "https://example.invalid/l")!, scope: "test")
        let consent = ConsentStore(defaults: h.defaults())

        let declined = h.model("start-declined"); h.watched.append(declined)
        check(await h.requests([.http(200, [:], validBody)]) { declined.autoStart(consented: consent.isAccepted(terms)) } == 0
              && !declined.enabled, "not accepted (or declined): no worker start, no request")

        consent.accept(terms)
        let configured = h.model("start-configured"); h.watched.append(configured)
        check(configured.status == .needsToken, "before startup: no token state known, nothing running")
        check(await h.requests([.http(200, [:], validBody)]) { configured.autoStart(consented: consent.isAccepted(terms)) } == 1,
              "accepted + saved token: starts automatically with exactly one request")
        check(configured.enabled && configured.status == .current, "accepted + saved token: data shown as current")

        let newBuild = LicenseTerms(version: "0.7.0", build: "12", notice: terms.notice, noticeSHA256: "aaa", legalSHA256: "bbb",
                                    noticeURL: terms.noticeURL, licenseURL: terms.licenseURL, scope: terms.scope)
        let changed = h.model("start-new-build"); h.watched.append(changed)
        check(await h.requests([.http(200, [:], validBody)]) { changed.autoStart(consented: consent.isAccepted(newBuild)) } == 0
              && !changed.enabled, "new build/terms identity: no start until accepted again")

        let unconfigured = h.model("start-unconfigured", token: nil); h.watched.append(unconfigured)
        check(await h.requests([]) { unconfigured.autoStart(consented: true) } == 0, "accepted, no token: no request")
        check(unconfigured.status == .needsToken && unconfigured.message.contains("Add a Cloudflare Radar Read token"),
              "accepted, no token: explains what is required")

        let cooldownDefaults = h.defaults()
        let cooling = h.model("start-cooldown", defaults: cooldownDefaults); h.watched.append(cooling)
        cooling.setNext(Date().addingTimeInterval(600))
        check(await h.requests([.http(200, [:], validBody)]) { cooling.autoStart(consented: true) } == 0,
              "accepted + token inside persisted cooldown: no request on relaunch")
        if case .waiting = cooling.status { check(cooling.enabled, "cooldown: enabled and shown as waiting") }
        else { check(false, "cooldown: enabled and shown as waiting") }

        let holder = h.model("start-conflict"); _ = holder
        let blocked = h.model("start-conflict"); h.watched.append(blocked)
        check(await h.requests([.http(200, [:], validBody)]) { blocked.autoStart(consented: true) } == 0
              && blocked.status == .otherWorker, "second window: refused worker never starts or requests")

        // Pause is remembered across relaunch; Start resumes.
        let pauseDefaults = h.defaults()
        let paused = h.model("start-paused", defaults: pauseDefaults); h.watched.append(paused)
        paused.autoStart(consented: true); paused.stop()
        let pausedAgain = h.model("start-paused-relaunch", defaults: pauseDefaults); h.watched.append(pausedAgain)
        check(await h.requests([.http(200, [:], validBody)]) { pausedAgain.autoStart(consented: true) } == 0
              && pausedAgain.status == .paused, "paused by the user: stays paused after relaunch")

        // A refused token is not retried on relaunch; saving a new token starts collection directly.
        let deniedDefaults = h.defaults()
        var current: String? = "refused-test-token"
        let refused = h.model("start-denied", defaults: deniedDefaults, token: { current }); h.watched.append(refused)
        check(await h.requests([.http(403, [:], Data())]) { refused.autoStart(consented: true) } == 1
              && refused.status == .denied, "403 at startup: one request, shown as refused")
        let relaunchedDenied = h.model("start-denied-relaunch", defaults: deniedDefaults, token: { current })
        h.watched.append(relaunchedDenied)
        relaunchedDenied.setNext(.distantPast)
        check(await h.requests([.http(200, [:], validBody)]) { relaunchedDenied.autoStart(consented: true) } == 0
              && relaunchedDenied.status == .denied, "refused token: no automatic retry after relaunch, even when eligible")
        check(await h.requests([.http(200, [:], validBody)]) {
            relaunchedDenied.save(token: "replacement-test-token"); current = "replacement-test-token"
        } == 1 && relaunchedDenied.status == .current, "saving a new token starts collection at once, no Start press")

        let firstRun = h.model("start-first-run", token: { current }, saved: { _ in false }); h.watched.append(firstRun)
        check(await h.requests([]) { firstRun.save(token: "x") } == 0 && firstRun.message.contains("Keychain save failed"),
              "Keychain save failure: no request, visible reason")

        check(Set(StubProtocol.hosts) == ["api.cloudflare.com"], "every intercepted request targeted api.cloudflare.com only")
        print("PASS: \(StubProtocol.hosts.count) stubbed requests, 0 network requests")
    }
}
