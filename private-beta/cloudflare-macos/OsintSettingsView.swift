import SwiftUI
import AppKit

/// Guide for adding the user's own API keys; lives on GitHub to keep the app small.
let osintKeyGuideURL = URL(string: "https://github.com/ibert-ai/threat-atlas/blob/main/docs/OSINT-API-KEYS.md")!
let releasesURL = URL(string: "https://github.com/ibert-ai/threat-atlas/releases")!

struct OsintPage: Identifiable { let id = UUID(); let title: String; let text: String }

/// The one Settings window: data sources on/off, viewing data, key guide, updates and the Radar token.
struct OsintSettingsView: View {
    @ObservedObject private var osint = OsintController.shared
    @State private var page: OsintPage?
    @State private var confirmLookup: String?
    private var version: String {
        let v = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let b = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        return "\(v) (build \(b))"
    }

    var body: some View {
        Form {
            Section {
                Text("Turn a source off and it makes no requests at all. Sources added in this version start off, except the four from the first release (CISA KEV/EPSS, Tor exits, SANS ISC). All are for non-commercial use unless the licence says otherwise.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            Section("Data sources") {
                ForEach(osint.sources) { source in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Toggle(source.name, isOn: Binding(get: { osint.isOn(source.id) }, set: { osint.set(source.id, on: $0) }))
                            Spacer()
                            Button("View") { page = OsintPage(title: source.name, text: osint.page(source)) }
                                .disabled(!osint.isOn(source.id))
                            if source.id == "shodan-internetdb" {
                                Button("Look up copied IP…") { askLookup() }.disabled(!osint.isOn(source.id))
                            }
                        }
                        Text(source.what).font(.caption)
                        Text(osint.status(source)).font(.caption).foregroundStyle(osint.isOn(source.id) ? Color.accentColor : Color.secondary)
                            .id(osint.tick)
                        Text("\(source.licence) Interval at least \(source.min_minutes) min. \(source.requires_key ? "Needs your own API key." : "No key needed.")")
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                }
                Button("Refresh data now") { osint.refresh() }
                Text("Refresh asks every switched-on source for new data, but each source keeps its own minimum interval (see the grey line), so some will say they are already up to date. The data is shown as text here for now; map panels come next.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("API keys") {
                Text("Sources that need your own API key will appear here once their key entry is added. Step-by-step instructions for every provider are kept on GitHub.")
                    .font(.callout).foregroundStyle(.secondary)
                Button("How to add API keys (opens GitHub)…") { NSWorkspace.shared.open(osintKeyGuideURL) }
            }
            Section("Cloudflare Radar") {
                Button("Cloudflare token…") { NotificationCenter.default.post(name: .showTokenSettings, object: nil) }
                Button("How to get a Cloudflare token…") { openTokenGuide() }
            }
            Section("Updates") {
                Text("Installed: AtlasSOC \(version). This beta is not Developer ID signed yet, so macOS may ask for approval the first time you open a new version.")
                    .font(.callout).foregroundStyle(.secondary)
                Button("Check for a newer version (opens GitHub releases)…") { NSWorkspace.shared.open(releasesURL) }
            }
        }
        .formStyle(.grouped)
        .onAppear { osint.startTicking() }
        .onDisappear { osint.stopTicking() }
        .frame(minWidth: 620, minHeight: 640)
        .sheet(item: $page) { p in
            VStack(alignment: .leading, spacing: 12) {
                Text(p.title).font(.headline)
                ScrollView { Text(p.text).font(.system(.body, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                HStack { Spacer(); Button("Done") { page = nil }.keyboardShortcut(.defaultAction) }
            }.padding(20).frame(width: 640, height: 460)
        }
        .alert("Send this address to Shodan?", isPresented: Binding(get: { confirmLookup != nil }, set: { if !$0 { confirmLookup = nil } })) {
            Button("Look up") {
                if let ip = confirmLookup, osint.lookup(ip) {
                    page = OsintPage(title: "Shodan InternetDB", text: "Lookup started. Close this window and press View in a few seconds.")
                }
                confirmLookup = nil
            }
            Button("Cancel", role: .cancel) { confirmLookup = nil }
        } message: {
            Text("\(confirmLookup ?? "") will be sent to internetdb.shodan.io. Shodan receives the address and your public IP address. Free for non-commercial use only. Answers are kept for 24 hours.")
        }
    }

    private func askLookup() {
        let text = OsintController.clipboardText().trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.count <= 64, !text.contains(where: \.isWhitespace) else {
            page = OsintPage(title: "Shodan InternetDB", text: "Copy one IP address first (for example 8.8.8.8), then press the button again. Nothing was sent.")
            return
        }
        confirmLookup = text
    }
}
