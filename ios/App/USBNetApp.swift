// USB Net (iPhone). Finds a Mac running usbnet on the USB cable and routes the phone's
// web traffic through it, using a VPN profile that only sets a proxy.
import Network
import NetworkExtension
import SwiftUI

@main
struct USBNetApp: App {
  var body: some Scene { WindowGroup { ContentView() } }
}

struct Mac: Identifiable, Hashable {
  let name: String
  let host: String
  let port: Int
  var id: String { "\(host):\(port)" }
}

/// Browses Bonjour for _usbnet._tcp. The Mac puts its USB link address in the TXT record.
@MainActor
final class Finder: ObservableObject {
  @Published var macs: [Mac] = []
  private var browser: NWBrowser?

  func start() {
    let params = NWParameters()
    params.includePeerToPeer = false
    let b = NWBrowser(for: .bonjourWithTXTRecord(type: "_usbnet._tcp", domain: nil), using: params)
    b.browseResultsChangedHandler = { [weak self] results, _ in
      var found: [Mac] = []
      for r in results {
        guard case let .service(name, _, _, _) = r.endpoint,
              case let .bonjour(txt) = r.metadata,
              let host = txt["addr"], host.hasPrefix("169.254.") else { continue }
        let port = Int(txt["port"] ?? "") ?? 8888
        found.append(Mac(name: name, host: host, port: port))
      }
      Task { @MainActor in self?.macs = Array(Set(found)).sorted { $0.name < $1.name } }
    }
    b.start(queue: .main)
    browser = b
  }

  func stop() { browser?.cancel(); browser = nil }
}

struct ContentView: View {
  @StateObject private var finder = Finder()
  @State private var status: NEVPNStatus = .invalid
  @State private var error: String?
  @State private var manual = false
  @AppStorage("host") private var host = ""
  @AppStorage("port") private var port = "8888"

  var body: some View {
    NavigationStack {
      List {
        Section {
          HStack(spacing: 12) {
            Circle().fill(status == .connected ? .green : .secondary.opacity(0.4)).frame(width: 12, height: 12)
            Text(statusText).font(.headline)
          }
          if status == .connected || status == .connecting {
            Button("Disconnect", role: .destructive) { Task { await disconnect() } }
          }
        }
        if status != .connected {
          Section {
            if finder.macs.isEmpty && !manual {
              Label("Looking for a Mac on the USB cable…", systemImage: "cable.connector")
                .foregroundStyle(.secondary)
            }
            ForEach(finder.macs) { mac in
              Button { Task { await connect(mac.host, mac.port) } } label: {
                Label("Connect to \(mac.name)", systemImage: "laptopcomputer")
              }
            }
          } header: { Text("Mac") } footer: {
            Text("Plug the iPhone into the Mac with a cable. The Mac must run USB Net.")
          }
          Section {
            DisclosureGroup("Enter address", isExpanded: $manual) {
              TextField("169.254.x.x", text: $host).keyboardType(.numbersAndPunctuation)
                .autocorrectionDisabled().textInputAutocapitalization(.never)
              TextField("Port", text: $port).keyboardType(.numberPad)
              Button("Connect") { Task { await connect(host, Int(port) ?? 8888) } }.disabled(host.isEmpty)
            }
          }
        }
        if let error { Section { Text(error).foregroundStyle(.red) } }
      }
      .navigationTitle("USB Net")
      .task { finder.start(); await refresh() }
      .onReceive(NotificationCenter.default.publisher(for: .NEVPNStatusDidChange)) { _ in Task { await refresh() } }
    }
  }

  private var statusText: String {
    switch status {
    case .connected: return "Connected through your Mac"
    case .connecting, .reasserting: return "Connecting…"
    case .disconnecting: return "Disconnecting…"
    default: return "Not connected"
    }
  }

  private func manager() async throws -> NETunnelProviderManager {
    try await NETunnelProviderManager.loadAllFromPreferences().first ?? NETunnelProviderManager()
  }

  private func connect(_ host: String, _ port: Int) async {
    error = nil
    do {
      let m = try await manager()
      let proto = NETunnelProviderProtocol()
      proto.providerBundleIdentifier = (Bundle.main.bundleIdentifier ?? "") + ".tunnel"
      proto.serverAddress = "\(host):\(port)"
      proto.providerConfiguration = ["host": host, "port": port]
      m.protocolConfiguration = proto
      m.localizedDescription = "USB Net"
      m.isEnabled = true
      try await m.saveToPreferences()
      try await m.loadFromPreferences()
      try m.connection.startVPNTunnel()
    } catch {
      self.error = error.localizedDescription
    }
    for _ in 0..<6 {  // the status notification can arrive before the new manager is loaded
      await refresh()
      if status == .connected { break }
      try? await Task.sleep(for: .milliseconds(500))
    }
  }

  private func disconnect() async {
    (try? await manager())?.connection.stopVPNTunnel()
  }

  private func refresh() async {
    status = (try? await manager())?.connection.status ?? .invalid
  }
}
