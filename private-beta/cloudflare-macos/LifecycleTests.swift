import Foundation
// Offline request-policy lifecycle tests for RadarModel. StubProtocol replaces every URL protocol in the
// worker's session, so nothing reaches the network. Each model uses a temporary directory, a private
// defaults suite and a fixed fake token: no Keychain, no real app data, no Cloudflare request.
// Run: xcrun swiftc -parse-as-library RadarCore.swift RadarModel.swift LifecycleTests.swift -o /private/tmp/radar-lifecycle-tests && /private/tmp/radar-lifecycle-tests

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
        RadarModel(directory: root.appendingPathComponent(dir, isDirectory: true), defaults: defaults ?? self.defaults(),
                   token: { token }, tokenExists: { token != nil }, saveToken: { _ in true }, protocolClasses: [StubProtocol.self])
    }
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

        // Configured state: a 200 marks the saved token as working and persists it with the polling
        // choice, so the next launch hides the token setup and resumes; 401 shows the setup again.
        let cd = h.defaults()
        let setup = h.model("configured", defaults: cd)
        check(setup.hasToken && !setup.configured, "fresh token: setup shown until Cloudflare accepts it")
        _ = await h.poll(setup, [.http(200, [:], validBody)])
        check(setup.configured, "200: token marked working, compact window")
        setup.start()   // user choice: polling on (next interval still blocks a request)
        let next = h.model("configured-relaunch", defaults: cd)
        let count = StubProtocol.hosts.count
        next.resumeIfConfigured()
        check(next.configured && next.enabled && StubProtocol.hosts.count == count, "relaunch: compact window, polling resumed, interval honoured")
        next.stop()
        let paused = h.model("configured-paused", defaults: cd)
        paused.resumeIfConfigured()
        check(paused.configured && !paused.enabled, "relaunch after Pause: polling stays paused")
        _ = await h.poll(paused, [.http(401, [:], Data())])
        check(!paused.configured && !h.model("configured-denied", defaults: cd).configured, "401: setup shown again, also after relaunch")
        let missing = h.model("configured-missing", defaults: cd, token: nil)
        check(!missing.configured, "no token in Keychain: setup shown")
        missing.save(token: "replacement-fake-token")
        check(missing.hasToken && !missing.configured, "new token saved: unverified until Cloudflare accepts it")
        StubProtocol.queue = []

        check(Set(StubProtocol.hosts) == ["api.cloudflare.com"], "every intercepted request targeted api.cloudflare.com only")
        print("PASS: \(StubProtocol.hosts.count) stubbed requests, 0 network requests")
    }
}
