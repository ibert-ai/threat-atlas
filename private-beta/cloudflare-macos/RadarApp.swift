import SwiftUI
import Combine

struct RadarView: View {
    @StateObject private var model = RadarModel()
    @State private var token = ""
    @State private var showAtlas = true
    private let timer = Timer.publish(every: 30, on: .main, in: .common).autoconnect()
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Threat Atlas · Cloudflare Radar").font(.largeTitle.bold())
            Text("PRIVATE macOS BETA 0.1 · Separate source preview").foregroundStyle(.orange)
            Text("Aggregated past-day attack origins, not individual live threats. No source/destination routes or benign/suspicious classifications are inferred.")
            HStack {
                SecureField("Cloudflare API token · Account / Radar / Read", text: $token)
                Button("Save in Keychain") { model.save(token: token); token = "" }
            }
            HStack {
                Button("Start") { model.start() }.disabled(model.enabled)
                Button("Pause") { model.stop() }.disabled(!model.enabled)
                Text(model.busy ? "Fetching…" : model.enabled ? "Polling enabled · at most once per 15 minutes" : "Polling paused")
            }
            Text(model.message).font(.headline)
            if let received = model.received {
                Text("Received: \(received.formatted()) · \(Date().timeIntervalSince(received) > 1800 ? "STALE CACHE" : "cached snapshot")")
            }
            if model.enabled { Text("Next eligible request: \(model.next.formatted())").font(.caption) }
            Picker("View", selection: $showAtlas) {
                Text("Atlas (shared core)").tag(true)
                Text("Table").tag(false)
            }.pickerStyle(.segmented).frame(maxWidth: 420)
            if showAtlas {
                CoreAtlasView(result: model.result, received: model.received)
            } else if let result = model.result {
                Text("Provider updated: \(result.meta.lastUpdated) · normalization: \(result.meta.normalization)")
                ForEach(result.meta.dateRange.indices, id: \.self) { i in
                    Text("Window: \(result.meta.dateRange[i].startTime) – \(result.meta.dateRange[i].endTime)").font(.caption)
                }
                Table(displayRows(result.top_0)) {
                    TableColumn("Origin entry") { item in Text(item.row.originCountryName) }
                    TableColumn("Country") { item in Text(item.row.originCountryAlpha2) }
                    TableColumn("Target") { item in Text(item.row.targetCountryAlpha2 ?? "not supplied") }
                    TableColumn("Provider value") { item in Text(item.row.value) }
                }
            } else {
                Spacer(); Text("No authenticated Cloudflare data has been received. No sample telemetry is displayed.").foregroundStyle(.secondary); Spacer()
            }
            Text("Uses api.cloudflare.com only · TLS verified · no browser cookies · token stays in this Mac’s Keychain").font(.caption).foregroundStyle(.secondary)
        }.padding(24).frame(minWidth: 1000, minHeight: 760)
        .onReceive(timer) { _ in Task { await model.refresh() } }
    }
}
@main struct PrivateRadarApp: App {
    var body: some Scene { WindowGroup { RadarView() } }
}
