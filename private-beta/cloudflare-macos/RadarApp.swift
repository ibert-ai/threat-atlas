import SwiftUI
import Combine
import AppKit

/// Opens the read-only customer token guide (HTML) that build.sh renders into the app bundle.
/// Returns false when the guide is missing from this build or no app could open it.
@discardableResult
func openTokenGuide() -> Bool {
    guard let url = Bundle.main.url(forResource: "Cloudflare-Radar-Token-Guide", withExtension: "html") else {
        return false
    }
    return NSWorkspace.shared.open(url)
}

extension Notification.Name {
    /// Sent by the AtlasSOC menu command; the window shows the Cloudflare token sheet.
    static let showTokenSettings = Notification.Name("atlasSOC.showTokenSettings")
}

struct RadarView: View {
    @StateObject private var model = RadarModel()
    @State private var showAtlas = true
    @State private var showTokenSheet = false
    /// True while the window is in macOS fullscreen: SOC mode shows only the map, edge to edge.
    @State private var fullScreen = false
    @State private var showExitHint = false
    private let timer = Timer.publish(every: 30, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(alignment: .leading, spacing: fullScreen ? 0 : 14) {
            if !fullScreen {
                // Compact window with the map: everything sits in the map's controls row.
                if !model.configured { setupHeader } else if !showAtlas { compactHeader }
                if !model.configured {
                    Picker("View", selection: $showAtlas) {
                        Text("Live SOC").tag(true)
                        Text("Table").tag(false)
                    }.pickerStyle(.segmented).frame(maxWidth: 420)
                }
            }
            if showAtlas || fullScreen {
                CoreAtlasView(result: model.result, received: model.received, showControls: !fullScreen,
                              leading: model.configured ? AnyView(statusItems) : nil,
                              trailing: model.configured ? AnyView(appButtons) : nil)
            } else {
                radarTable
            }
            if !fullScreen { attribution }
        }
        .padding(fullScreen ? 0 : 24)
        .frame(minWidth: 1000, minHeight: 760)
        .background(fullScreen ? Color.black : Color.clear)
        .ignoresSafeArea(edges: fullScreen ? .all : [])
        .overlay(alignment: .bottomTrailing) {
            // Cloudflare's CC BY-NC 4.0 terms require attribution, also on a wall display.
            if fullScreen {
                Text("Data: GreyNoise · Cloudflare Radar (CC BY-NC 4.0)")
                    .font(.caption2).foregroundStyle(.white.opacity(0.45)).padding(6)
            }
        }
        .overlay(alignment: .top) {
            if showExitHint {
                Text("SOC fullscreen · press Esc or ⌃⌘F to show the controls")
                    .font(.callout).padding(.horizontal, 14).padding(.vertical, 8)
                    .background(.black.opacity(0.75), in: Capsule()).foregroundStyle(.white)
                    .padding(.top, 18).transition(.opacity)
            }
        }
        .background {
            // Esc leaves SOC fullscreen (macOS has no default Esc for app fullscreen).
            if fullScreen {
                Button("") { NSApp.keyWindow?.toggleFullScreen(nil) }
                    .keyboardShortcut(.escape, modifiers: []).opacity(0)
            }
        }
        .sheet(isPresented: $showTokenSheet) { TokenSettings(model: model) }
        .onReceive(timer) { _ in Task { await model.refresh() } }
        .onReceive(NotificationCenter.default.publisher(for: .showTokenSettings)) { _ in showTokenSheet = true }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didEnterFullScreenNotification)) { _ in
            fullScreen = true
            withAnimation { showExitHint = true }
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { withAnimation { showExitHint = false } }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didExitFullScreenNotification)) { _ in
            fullScreen = false; showExitHint = false
        }
        .onAppear { model.resumeIfConfigured() }
    }

    /// First run, or the token is missing or no longer accepted: the full setup and explanation.
    private var setupHeader: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Threat Atlas SOC").font(.largeTitle.bold())
            Text("AtlasSOC BETA \(radarLicenseTerms.version) · build \(radarLicenseTerms.build) · Ibert Consulting").foregroundStyle(.orange)
            Text("Live: GreyNoise public threat-map records as received (not unique attacks), classified by the provider. Cloudflare Radar: past-day aggregate shares; never turned into routes or individual events.")
            TokenEntry(model: model)
            pollingRow
            Text(model.message).font(.headline)
            receivedLine
            if model.enabled { Text("Next eligible request: \(model.next.formatted())").font(.caption) }
        }
    }

    /// Token saved and working (Table view): one line of status and buttons.
    private var compactHeader: some View {
        HStack(spacing: 12) { statusItems; Spacer(); appButtons }
    }

    /// Title, beta label and Radar state; details (received time, last message) in the tooltip.
    private var statusItems: some View {
        HStack(spacing: 8) {
            Text("Threat Atlas SOC").font(.headline)
            Text("BETA \(radarLicenseTerms.version) · \(radarLicenseTerms.build)").font(.caption).foregroundStyle(.orange)
            Circle().fill(model.enabled ? Color.green : Color.secondary).frame(width: 8, height: 8)
            Text(model.busy ? "Radar…" : model.enabled ? "Radar on" : "Radar paused").font(.callout)
        }
        .fixedSize()
        .help(radarDetails)
    }

    private var radarDetails: String {
        var lines = [model.message]
        if let received = model.received {
            lines.append("Received: \(received.formatted())\(Date().timeIntervalSince(received) > 1800 ? " · STALE" : "")")
        }
        if model.enabled { lines.append("Next eligible request: \(model.next.formatted())") }
        return lines.joined(separator: "\n")
    }

    private var appButtons: some View {
        HStack(spacing: 8) {
            Picker("View", selection: $showAtlas) {
                Text("Live SOC").tag(true)
                Text("Table").tag(false)
            }.pickerStyle(.segmented).labelsHidden().frame(width: 150)
            Button(model.enabled ? "Pause Radar" : "Start Radar") { model.enabled ? model.stop() : model.start() }
            Button("Token…") { showTokenSheet = true }.help("Change the Cloudflare token (also AtlasSOC ▸ Cloudflare Token…, ⌘,)")
        }
        .fixedSize()
    }

    private var pollingRow: some View {
        HStack {
            Button("Start") { model.start() }.disabled(model.enabled)
            Button("Pause") { model.stop() }.disabled(!model.enabled)
            Text(model.busy ? "Fetching…" : model.enabled ? "Polling enabled · at most once per 15 minutes" : "Polling paused")
        }
    }

    @ViewBuilder private var receivedLine: some View {
        if let received = model.received {
            Text("Received: \(received.formatted()) · \(Date().timeIntervalSince(received) > 1800 ? "STALE CACHE" : "cached snapshot")")
        }
    }

    @ViewBuilder private var radarTable: some View {
        if let result = model.result {
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
    }

    private var attribution: some View {
        HStack(spacing: 4) {
            Text("Cloudflare Radar data: CC BY-NC 4.0, non-commercial use only · attribution: Cloudflare Radar ·")
            Link("licence", destination: radarLicenseTerms.licenseURL)
        }
        .font(.caption).foregroundStyle(.secondary)
        .help("Network: threat-map-api.greynoise.io (live feed) · api.cloudflare.com (Radar, only after Start) · TLS verified · no browser cookies · token stays in this Mac’s Keychain")
    }
}

/// Token field, save and guide button: shown in the setup header and in the token sheet.
struct TokenEntry: View {
    @ObservedObject var model: RadarModel
    @State private var token = ""
    var body: some View {
        HStack {
            SecureField("Cloudflare API token · Account / Radar / Read", text: $token)
            Button("Save in Keychain") { model.save(token: token); token = "" }
            Button("How to get a token…") {
                if !openTokenGuide() {
                    model.message = "The token guide could not be opened. See CLOUDFLARE-RADAR-TOKEN-GUIDE.md in the AtlasSOC documentation."
                }
            }
        }
    }
}

/// AtlasSOC ▸ Cloudflare Token…: change the token once one is saved and working.
struct TokenSettings: View {
    @ObservedObject var model: RadarModel
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Cloudflare Radar token").font(.title2.bold())
            Text(model.configured ? "A working token is saved in this Mac’s Keychain. Paste a new one to replace it."
                                  : "No working token is saved yet.")
            TokenEntry(model: model)
            Text(model.message).font(.callout).foregroundStyle(.secondary)
            Text("To remove the token from this Mac, delete “ThreatAtlas.PrivateRadarBeta” in Keychain Access. To cancel it everywhere, delete it in Cloudflare under My Profile → API Tokens.")
                .font(.caption).foregroundStyle(.secondary)
            Text("Network: threat-map-api.greynoise.io (live feed) · api.cloudflare.com (Radar, only after Start) · TLS verified · no browser cookies · token stays in this Mac’s Keychain")
                .font(.caption).foregroundStyle(.secondary)
            HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.defaultAction) }
        }
        .padding(24).frame(width: 720)
    }
}
@main struct PrivateRadarApp: App {
    // The licence gate wraps everything: no feed, worker or Keychain access before acceptance.
    var body: some Scene {
        WindowGroup { ConsentGate(terms: radarLicenseTerms) { RadarView() } }
            .commands {
                CommandGroup(after: .appSettings) {
                    Button("Cloudflare Token…") { NotificationCenter.default.post(name: .showTokenSettings, object: nil) }
                        .keyboardShortcut(",", modifiers: [.command])
                }
            }
    }
}
