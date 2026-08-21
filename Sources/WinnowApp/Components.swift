import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit
import UniformTypeIdentifiers
import WebKit

/// How long a copied item lives, and whether it may leave the device.
///
/// The clipboard is the one place wallet material sits outside the app's
/// control, and iOS syncs the general pasteboard to a user's other Apple
/// devices unless told not to. The two policies below are different on
/// purpose.
struct ClipboardPolicy: Equatable {
    /// Whether the item may leave this device via Universal Clipboard.
    var localOnly: Bool
    /// How long before the system drops it.
    var lifetime: TimeInterval

    /// Recovery words never leave the device, and expire quickly. There is no
    /// legitimate reason to move a seed between devices by clipboard.
    static let recoveryPhrase = ClipboardPolicy(localOnly: true, lifetime: 120)

    /// Descriptors, PSBTs and addresses may cross to a desktop, because that
    /// is a real workflow — a k-of-n vault's watch-only descriptor is meant to
    /// be pasted into Bitcoin Core, and a PSBT travels between cosigners.
    ///
    /// The accepted risk is therefore Universal Clipboard, not the copy
    /// itself: a descriptor carries xpubs, so whoever holds it can derive
    /// every address the vault will ever use. Blocking that sync would break
    /// the workflow the feature exists for, so the item still expires rather
    /// than sitting on the pasteboard until something else overwrites it.
    static let interchange = ClipboardPolicy(localOnly: false, lifetime: 300)

    var options: [UIPasteboard.OptionsKey: Any] {
        [.localOnly: localOnly, .expirationDate: Date().addingTimeInterval(lifetime)]
    }

    /// Single place any wallet material reaches the pasteboard, so a new copy
    /// button has to state which policy it wants.
    func apply(_ text: String, to pasteboard: UIPasteboard = .general) {
        pasteboard.setItems([[UTType.plainText.identifier: text]], options: options)
    }
}

/// An explicit, short-lived clipboard handoff for recovery words.
struct RecoveryPhraseCopyButton: View {
    let phrase: String
    let accessibilityID: String
    @State private var copied = false

    var body: some View {
        Button(copied ? "Copied for 2 minutes" : "Copy recovery phrase") {
            ClipboardPolicy.recoveryPhrase.apply(phrase)
            copied = true
        }
        .accessibilityIdentifier(accessibilityID)
    }
}

/// A user-initiated handoff to the selected external block explorer. Merely
/// rendering this view performs no request; the exact host and privacy leak
/// are confirmed immediately before iOS opens the URL.
struct WarnedExplorerLink: View {
    let title: String
    let url: URL
    let exposedItem: String
    let accessibilityID: String

    @Environment(\.openURL) private var openURL
    @State private var showingWarning = false

    var body: some View {
        Button {
            showingWarning = true
        } label: {
            Label(title, systemImage: "safari")
        }
        .accessibilityIdentifier(accessibilityID)
        .alert("Open external block explorer?", isPresented: $showingWarning) {
            Button("Open \(url.host ?? "explorer")") { openURL(url) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Opening \(url.host ?? "this explorer") shares your IP address and this exact \(exposedItem) with that service. Winnow does not use its response for wallet balance, history, fees, synchronization, or broadcasting.")
        }
    }
}

/// Address/PSBT QR via CoreImage's CIQRCodeGenerator.
struct QRCodeView: View {
    let content: String

    private var image: UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(content.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 12, y: 12))
        guard let cgImage = CIContext().createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }

    var body: some View {
        if let image {
            Image(uiImage: image)
                .resizable()
                .interpolation(.none)
                .scaledToFit()
        } else {
            ContentUnavailableView("QR unavailable", systemImage: "qrcode")
        }
    }
}

/// A scrollable monospaced blob (address, descriptor, PSBT) with copy/share.
struct CopyableTextBlock: View {
    let text: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ScrollView {
                Text(text)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 120)
            HStack {
                Button("Copy") { ClipboardPolicy.interchange.apply(text) }
                ShareLink(item: text)
            }
            .buttonStyle(.bordered)
        }
    }
}

/// The bundled design papers are the same HTML the website serves. Loading the
/// file from the bundle keeps them readable with no network, and lets the page
/// bring its own typography instead of being flattened into one Text view.
private struct BundledPageView: UIViewRepresentable {
    let url: URL

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        // site.css hides the site's own nav and footer under .embedded; the
        // sheet supplies that chrome already.
        config.userContentController.addUserScript(
            WKUserScript(source: "document.body.classList.add('embedded')",
                         injectionTime: .atDocumentEnd,
                         forMainFrameOnly: true))
        let view = WKWebView(frame: .zero, configuration: config)
        view.isOpaque = false
        view.backgroundColor = .systemBackground
        // read access to the whole bundle directory so the page can pull site.css
        view.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        return view
    }

    func updateUIView(_ view: WKWebView, context: Context) {}
}

/// A bundled design paper, rendered from the page the site serves so Settings
/// can open it offline.
struct DesignPaperView: View {
    let resource: String
    let title: String

    var body: some View {
        Group {
            if let url = Bundle.main.url(forResource: resource, withExtension: "html") {
                BundledPageView(url: url)
            } else {
                ScrollView {
                    Text("The bundled copy of docs/\(resource).html could not be loaded.")
                        .font(.footnote)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                }
            }
        }
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
    }
}

/// The bundled design paper (docs/read-side.html) so the esplora opt-in
/// warning can link to it offline.
struct ReadSideDocumentView: View {
    var body: some View {
        NavigationStack {
            DesignPaperView(resource: "read-side", title: "The Read Side")
        }
    }
}

/// Index of the bundled design papers (docs/).
struct DesignPapersView: View {
    private struct Paper: Identifiable {
        var id: String { resource }
        let resource: String
        let title: String
        let blurb: String
    }

    private let papers: [Paper] = [
        Paper(resource: "mobile", title: "A phone wallet",
              blurb: "What the device forces, and what the product refuses."),
        Paper(resource: "read-side", title: "The read side",
              blurb: "How the phone learns which coins are its own."),
        Paper(resource: "write-side", title: "The write side",
              blurb: "Build, price, sign, and get a transaction out."),
        Paper(resource: "vaults", title: "Vaults",
              blurb: "Shared custody without a coordinator server."),
        Paper(resource: "import", title: "Import",
              blurb: "The bundle is the history. There is no back-scan."),
    ]

    var body: some View {
        NavigationStack {
            List(papers) { paper in
                NavigationLink {
                    DesignPaperView(resource: paper.resource, title: paper.title)
                } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(paper.title)
                        Text(paper.blurb)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Design papers")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

/// Sats with thousands separators plus the unit.
func satsText(_ amount: Int64) -> String {
    "\(amount.formatted()) sats"
}

/// A double sat/vB rate, trimmed of trailing zeros.
func feeRateText(_ rate: Double) -> String {
    "\(rate.formatted(.number.precision(.fractionLength(0 ... 2)))) sat/vB"
}
