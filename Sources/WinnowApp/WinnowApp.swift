import BitcoinP2P
import SwiftUI
import UIKit

@main
struct WinnowApp: App {
    @State private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            Group {
                switch model.stage {
                case .loading:
                    ProgressView("Opening wallet…")
                case .onboarding:
                    OnboardingView()
                case .ready:
                    MainTabView()
                case let .storageDamaged(message):
                    StorageDamagedView(message: message)
                }
            }
            .redacted(reason: shouldObscureWallet(for: scenePhase) ? .privacy : [])
            .accessibilityHidden(shouldObscureWallet(for: scenePhase))
            .environment(model)
            .task { await model.boot() }
            .onAppear {
                PrivacyShield.shared.setObscured(shouldObscureWallet(for: scenePhase))
            }
            .onChange(of: scenePhase) { _, phase in
                // A separate high-level UIWindow sits above SwiftUI sheets and
                // full-screen covers. A cover inside this root hierarchy would
                // remain behind presented recovery/signing sheets when iOS
                // records its app-switcher snapshot.
                PrivacyShield.shared.setObscured(shouldObscureWallet(for: phase))
                model.scenePhaseChanged(phase)
            }
        }
    }
}

struct StorageDamagedView: View {
    let message: String
    @Environment(AppModel.self) private var model

    private var otherNetwork: BitcoinNetwork {
        model.network == .mainnet ? .signet : .mainnet
    }

    var body: some View {
        ContentUnavailableView {
            Label("Wallet data needs attention", systemImage: "externaldrive.badge.exclamationmark")
        } description: {
            Text(message)
        } actions: {
            Button("Retry without changing anything") {
                Task { await model.retryWalletOpen() }
            }
            .buttonStyle(.borderedProminent)
            .accessibilityIdentifier("retryDamagedWalletButton")
            Button("Open the \(otherNetwork.rawValue) wallet instead") {
                Task { await model.switchNetwork(to: otherNetwork) }
            }
            .accessibilityIdentifier("switchFromDamagedWalletButton")
        }
        .padding()
    }
}

/// A tiny pure policy so active/inactive/background behavior is deterministic
/// and covered without trying to introspect an iOS app-switcher snapshot.
func shouldObscureWallet(for phase: ScenePhase) -> Bool {
    switch phase {
    case .active: false
    case .inactive, .background: true
    @unknown default: true
    }
}

private struct AppPrivacyCover: View {
    var body: some View {
        ZStack {
            Color(.systemBackground)
                .ignoresSafeArea()
            VStack(spacing: 12) {
                Image(systemName: "eye.slash")
                    .font(.system(size: 34, weight: .semibold))
                Text("Winnow is hidden")
                    .font(.headline)
            }
            .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Winnow is hidden while inactive")
    }
}

/// Owns an opaque window above every application presentation window while
/// the scene is inactive. Keeping this outside the SwiftUI presentation tree
/// is essential: `.sheet` content is hosted above its presenting view and
/// would otherwise remain visible in the app-switcher snapshot.
@MainActor
final class PrivacyShield {
    static let shared = PrivacyShield()

    private var windows: [ObjectIdentifier: UIWindow] = [:]

    private init() {}

    func setObscured(_ obscured: Bool) {
        if obscured {
            show()
        } else {
            hide()
        }
    }

    private func show() {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        let liveIDs = Set(scenes.map { ObjectIdentifier($0) })

        let staleIDs = windows.keys.filter { !liveIDs.contains($0) }
        for id in staleIDs {
            windows[id]?.isHidden = true
            windows.removeValue(forKey: id)
        }

        for scene in scenes {
            let id = ObjectIdentifier(scene)
            let window = windows[id] ?? makeWindow(for: scene)
            windows[id] = window
            window.isHidden = false
        }
    }

    private func hide() {
        // Hidden, but kept. The scene retains a window it owns regardless of
        // what this type does, so discarding our reference does not free it —
        // it only guarantees the next `show()` builds another one on top,
        // because the cache `show()` reads is then empty. Cycling the scene
        // phase twenty times used to leave twenty windows attached, and a
        // phone flips phase on every call, notification shade and app switch.
        for window in windows.values {
            window.isHidden = true
        }
    }

    private func makeWindow(for scene: UIWindowScene) -> UIWindow {
        let window = UIWindow(windowScene: scene)
        window.windowLevel = .alert + 1
        window.backgroundColor = .systemBackground
        window.isUserInteractionEnabled = false
        window.rootViewController = UIHostingController(rootView: AppPrivacyCover())
        window.accessibilityIdentifier = "appPrivacyCoverWindow"
        return window
    }
}

/// The four sections of the wallet shell.
struct MainTabView: View {
    private enum Tab: String, Hashable {
        case wallet, send, vaults, settings
    }

    @State private var selection: Tab

    init() {
        let requested = E2EMode.current?.initialTab.flatMap(Tab.init(rawValue:))
        _selection = State(initialValue: requested ?? .wallet)
    }

    var body: some View {
        TabView(selection: $selection) {
            HomeView()
                .tabItem { Label("Wallet", systemImage: "bitcoinsign.circle") }
                .tag(Tab.wallet)
            SendView()
                .tabItem { Label("Send", systemImage: "arrow.up.circle") }
                .tag(Tab.send)
            VaultsView()
                .tabItem { Label("Vaults", systemImage: "lock.shield") }
                .tag(Tab.vaults)
            SettingsView()
                .tabItem { Label("Settings", systemImage: "gear") }
                .tag(Tab.settings)
        }
    }
}
