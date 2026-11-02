import Foundation
// Licence consent rules. Offline, private defaults suite; never touches the real app's consent
// and never accepts through the UI on anyone's behalf.
// Run: xcrun swiftc -parse-as-library LicenseConsent.swift ConsentTests.swift -o /private/tmp/radar-consent-tests && /private/tmp/radar-consent-tests
func check(_ ok: Bool, _ what: String) { precondition(ok, what); print("ok  " + what) }

@main struct ConsentTests {
    static func main() {
        let suite = "ThreatAtlasConsentTests." + UUID().uuidString
        let defaults = UserDefaults(suiteName: suite)!
        defer { UserDefaults.standard.removePersistentDomain(forName: suite) }
        let store = ConsentStore(defaults: defaults)
        let terms = LicenseTerms(version: "0.7.0", build: "9", notice: "Synthetic notice for tests.",
                                 noticeSHA256: "aaa", legalSHA256: "bbb",
                                 noticeURL: URL(string: "https://example.invalid/notice")!,
                                 licenseURL: URL(string: "https://example.invalid/licence")!, scope: "test")
        let other = { (version: String, build: String, notice: String, legal: String) in
            LicenseTerms(version: version, build: build, notice: terms.notice, noticeSHA256: notice, legalSHA256: legal,
                         noticeURL: terms.noticeURL, licenseURL: terms.licenseURL, scope: terms.scope)
        }
        check(terms.consentKey == "0.7.0+9:aaa:bbb", "key = release+build:notice:legal (same shape as the PR #17 gate)")
        check(!store.isAccepted(terms), "first start: not accepted")
        store.accept(terms)
        check(store.isAccepted(terms), "accepted for this exact version/build/terms")
        check(!store.isAccepted(other("0.7.1", "9", "aaa", "bbb")), "new version requires acceptance again")
        check(!store.isAccepted(other("0.7.0", "10", "aaa", "bbb")), "new build requires acceptance again")
        check(!store.isAccepted(other("0.7.0", "9", "ccc", "bbb")), "changed Cloudflare notice requires acceptance again")
        check(!store.isAccepted(other("0.7.0", "9", "aaa", "ddd")), "changed licence legal code requires acceptance again")
        store.accept(other("0.7.1", "10", "aaa", "bbb"))
        check(!store.isAccepted(terms), "accepting a newer version does not carry back to the old one")
        print("PASS: consent gate rules")
    }
}
