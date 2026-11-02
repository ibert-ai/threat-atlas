import SwiftUI
import AppKit

// Cloudflare Radar data licence gate. Robert's rule (docs/CLOUDFLARE-RADAR-ALPHA.md, PR #17):
// mandatory acceptance on first start and again for every new version/build or changed terms;
// decline exits; only the person reviewing the terms may accept (tests never accept for them).
// The key matches the PR #17 Mac gate: release+build plus the reviewed notice/legal-code
// fingerprints from docs/CLOUDFLARE-LICENSE.json. build.sh generates `radarLicenseTerms` only
// after scripts/check-cloudflare-license.py confirms the published terms are unchanged.

struct LicenseTerms {
    let version: String
    let build: String
    let notice: String
    let noticeSHA256: String
    let legalSHA256: String
    let noticeURL: URL
    let licenseURL: URL
    let scope: String
    var consentKey: String { "\(version)+\(build):\(noticeSHA256):\(legalSHA256)" }
}

struct ConsentStore {
    static let defaultsKey = "cloudflareRadarConsent"
    let defaults: UserDefaults
    init(defaults: UserDefaults = .standard) { self.defaults = defaults }
    func isAccepted(_ terms: LicenseTerms) -> Bool {
        defaults.string(forKey: Self.defaultsKey) == terms.consentKey
    }
    /// Called only from the visible Accept button, after the acknowledgement is ticked.
    func accept(_ terms: LicenseTerms) { defaults.set(terms.consentKey, forKey: Self.defaultsKey) }
}

/// Shows the licence until accepted for this exact version/build/terms; nothing inside `content`
/// (GreyNoise feed, Cloudflare worker, Keychain) is created before that.
struct ConsentGate<Content: View>: View {
    let terms: LicenseTerms
    let store: ConsentStore
    @ViewBuilder let content: () -> Content
    @State private var accepted: Bool
    @State private var acknowledged = false

    init(terms: LicenseTerms, store: ConsentStore = ConsentStore(), @ViewBuilder content: @escaping () -> Content) {
        self.terms = terms
        self.store = store
        self.content = content
        _accepted = State(initialValue: store.isAccepted(terms))
    }

    var body: some View {
        if accepted { content() } else { consent }
    }

    private var consent: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Threat Atlas SOC · data licence").font(.title.bold())
            Text("Version \(terms.version) (build \(terms.build)). This is shown on first start and again for every new version or build. Nothing connects until you accept.")
                .foregroundStyle(.secondary)
            GroupBox("Cloudflare Radar · aggregate attack data") {
                VStack(alignment: .leading, spacing: 6) {
                    Text("“\(terms.notice)”").italic()
                    Text("Licence: Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0). Scope: \(terms.scope).")
                    HStack(spacing: 16) {
                        Link("Cloudflare Radar notice", destination: terms.noticeURL)
                        Link("CC BY-NC 4.0 legal code", destination: terms.licenseURL)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            GroupBox("GreyNoise public threat map · live records") {
                Text("Live records are read from GreyNoise's public threat map as received. Counts are received records, not unique attacks. No endorsement implied.")
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            Toggle("I have read the Cloudflare Radar notice and the CC BY-NC 4.0 licence. I will use Radar data only non-commercially and with attribution.",
                   isOn: $acknowledged)
            HStack {
                Button("Decline and quit", role: .cancel) { NSApplication.shared.terminate(nil) }
                Spacer()
                Button("Accept") {
                    store.accept(terms)
                    accepted = true
                }
                .disabled(!acknowledged)
                .keyboardShortcut(.defaultAction)
            }
            Text("Terms fingerprints · notice \(terms.noticeSHA256.prefix(12)) · legal code \(terms.legalSHA256.prefix(12))")
                .font(.caption.monospaced()).foregroundStyle(.secondary)
        }
        .padding(28)
        .frame(width: 720)
    }
}
