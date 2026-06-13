import SwiftUI
import UIKit
import NetworkExtension

/// Main screen. Deliberately a full utility (toggle, status, transport masking, secret
/// management, deeplink, logs) — not a one-button link opener — to satisfy App Review's
/// "minimum functionality" guideline and to be genuinely useful.
struct ContentView: View {
    @StateObject private var tunnel = TunnelController()
    @State private var settings = ProxySettings.load()
    @State private var showSecret = false

    private var isOn: Bool { tunnel.status == .connected || tunnel.status == .connecting }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    statusCard
                    maskingCard
                    secretCard
                    telegramButton
                }
                .padding()
            }
            .navigationTitle("Jevio Unlocker")
            .task { await tunnel.load() }
        }
    }

    // MARK: Status / toggle

    private var statusCard: some View {
        VStack(spacing: 12) {
            HStack {
                Circle()
                    .fill(statusColor)
                    .frame(width: 12, height: 12)
                Text(statusText).font(.headline)
                Spacer()
            }
            Toggle(isOn: Binding(
                get: { isOn },
                set: { on in Task { on ? await tunnel.start(settings) : tunnel.stop() } }
            )) {
                Text(isOn ? "Подключено" : "Отключено")
            }
            if let err = tunnel.lastError {
                Text(err).font(.caption).foregroundStyle(.red)
            }
        }
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16))
    }

    private var statusText: String {
        switch tunnel.status {
        case .connected: return "Туннель активен"
        case .connecting: return "Подключение…"
        case .disconnecting: return "Отключение…"
        case .disconnected, .invalid: return "Выключено"
        case .reasserting: return "Переподключение…"
        @unknown default: return "—"
        }
    }
    private var statusColor: Color {
        switch tunnel.status {
        case .connected: return .green
        case .connecting, .reasserting: return .yellow
        default: return .secondary
        }
    }

    // MARK: Masking (transport)

    private var maskingCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Маскировка (Fake TLS)").font(.subheadline.bold())
            Text("Домен, под HTTPS-сессию к которому маскируется трафик. Пусто = обычный режим.")
                .font(.caption).foregroundStyle(.secondary)
            TextField("www.cloudflare.com", text: $settings.fakeTlsDomain)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .textFieldStyle(.roundedBorder)
                .onChange(of: settings.fakeTlsDomain) { _, _ in settings.save() }
        }
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16))
    }

    // MARK: Secret

    private var secretCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Секрет прокси").font(.subheadline.bold())
            HStack {
                Text(showSecret ? settings.secretHex : String(repeating: "•", count: settings.secretHex.count))
                    .font(.system(.footnote, design: .monospaced))
                    .lineLimit(1).truncationMode(.middle)
                Spacer()
                Button { showSecret.toggle() } label: { Image(systemName: showSecret ? "eye.slash" : "eye") }
            }
            HStack {
                Button("Сгенерировать новый") {
                    settings.secretHex = SecretGenerator.generate(); settings.save()
                }
                Spacer()
                Button("Копировать") { UIPasteboard.general.string = settings.secretHex }
            }
            .font(.caption)
        }
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16))
    }

    // MARK: Telegram deeplink

    private var telegramButton: some View {
        Button {
            if let url = settings.telegramDeeplink { UIApplication.shared.open(url) }
        } label: {
            Label("Подключить Telegram", systemImage: "paperplane.fill")
                .frame(maxWidth: .infinity)
                .padding()
        }
        .buttonStyle(.borderedProminent)
        .disabled(!isOn)
    }
}
