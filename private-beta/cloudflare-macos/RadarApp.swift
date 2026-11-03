import SwiftUI
import Combine

struct RadarView: View {
    @StateObject private var model = RadarModel()
    @State private var token = ""
    @State private var showAtlas = true
    private let timer = Timer.publish(every: 30, on: .main, in: .common).autoconnect()
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Threat Atlas SOC").font(.largeTitle.bold())
            Text("AtlasSOC BETA \(radarLicenseTerms.version) · build \(radarLicenseTerms.build) · Ibert Consulting").foregroundStyle(.orange)
            Text("Live: GreyNoise public threat-map records as received (not unique attacks), classified by the provider. Cloudflare Radar: past-day aggregate shares; never turned into routes or individual events.")
            HStack {
                SecureField(model.hasToken ? "Token saved in Keychain · paste a new one to replace it"
                                           : "Cloudflare API token · Account / Radar / Read", text: $token)
                Button(model.hasToken ? "Replace token" : "Save and start") { model.save(token: token); token = "" }
                    .disabled(token.isEmpty)
            }
            HStack {
                Label(statusText, systemImage: statusIcon).font(.headline)
                Spacer()
                if model.status == .paused { Button("Start") { model.start() } }
                if model.enabled { Button("Pause") { model.stop() } }
            }
            Text(model.message).foregroundStyle(.secondary)
            if let received = model.received {
                Text("Received: \(received.formatted()) · \(Date().timeIntervalSince(received) > 1800 ? "STALE CACHE" : "cached snapshot")")
            }
            Picker("View", selection: $showAtlas) {
                Text("Live SOC").tag(true)
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
            Text("Network: threat-map-api.greynoise.io (live feed) · api.cloudflare.com (Radar, only after Start) · TLS verified · no browser cookies · token stays in this Mac’s Keychain").font(.caption).foregroundStyle(.secondary)
            HStack(spacing: 4) {
                Text("Cloudflare Radar data: CC BY-NC 4.0, non-commercial use only · attribution: Cloudflare Radar ·")
                Link("licence", destination: radarLicenseTerms.licenseURL)
            }
            .font(.caption).foregroundStyle(.secondary)
        }.padding(24).frame(minWidth: 1000, minHeight: 760)
        .onReceive(timer) { _ in Task { await model.refresh() } }
        // Only reachable after the licence gate; the check is repeated so the worker can never start without it.
        .onAppear { model.autoStart(consented: ConsentStore().isAccepted(radarLicenseTerms)) }
    }
    private var statusText: String {
        switch model.status {
        case .otherWorker: return "Radar: another AtlasSOC window is collecting. Use that window."
        case .needsToken: return "Radar: add a Read token to start (GreyNoise live data is already on)"
        case .denied: return "Radar: token refused by Cloudflare · save a new token"
        case .paused: return "Radar: paused"
        case let .waiting(date): return "Radar: waiting · next request \(date.formatted(date: .omitted, time: .shortened))"
        case .fetching: return "Radar: fetching…"
        case .current: return "Radar: current · next request \(model.next.formatted(date: .omitted, time: .shortened))"
        case .stale: return "Radar: stale cache · next request \(model.next.formatted(date: .omitted, time: .shortened))"
        case .unavailable: return "Radar: unavailable · retrying \(model.next.formatted(date: .omitted, time: .shortened))"
        }
    }
    private var statusIcon: String {
        switch model.status {
        case .current: return "checkmark.circle"
        case .fetching, .waiting: return "clock"
        case .paused: return "pause.circle"
        case .needsToken: return "key"
        default: return "exclamationmark.triangle"
        }
    }
}
@main struct PrivateRadarApp: App {
    // The licence gate wraps everything: no feed, worker or Keychain access before acceptance.
    var body: some Scene { WindowGroup { ConsentGate(terms: radarLicenseTerms) { RadarView() } } }
}
