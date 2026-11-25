import Network
import NetworkExtension

/// Sets a phone-wide HTTP/HTTPS proxy that points at the Mac on the USB link. The tunnel itself
/// carries no packets. Every 5 s it checks that the Mac still answers; after 3 misses (cable
/// unplugged, Mac asleep) it stops, so the phone goes back to its normal connection.
final class PacketTunnelProvider: NEPacketTunnelProvider {
  private var timer: DispatchSourceTimer?
  private var misses = 0
  private var host = ""
  private var port = 8888

  override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
    let cfg = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
    host = cfg["host"] as? String ?? ""
    port = cfg["port"] as? Int ?? 8888
    guard host.hasPrefix("169.254.") else {
      completionHandler(NSError(domain: "USBNet", code: 1, userInfo: [NSLocalizedDescriptionKey: "No Mac address"]))
      return
    }
    let s = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: host)
    let v4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.255.255"])
    v4.includedRoutes = []  // no routes: only proxied traffic goes to the Mac
    s.ipv4Settings = v4
    let server = NEProxyServer(address: host, port: port)
    let proxy = NEProxySettings()
    proxy.httpEnabled = true
    proxy.httpServer = server
    proxy.httpsEnabled = true
    proxy.httpsServer = server
    proxy.excludeSimpleHostnames = false
    proxy.matchDomains = [""]
    proxy.exceptionList = ["169.254.*", "localhost", "127.0.0.1", "*.local"]
    s.proxySettings = proxy
    setTunnelNetworkSettings(s) { [weak self] error in
      if error == nil { self?.startHealthCheck() }
      completionHandler(error)
    }
  }

  override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
    timer?.cancel()
    completionHandler()
  }

  private func startHealthCheck() {
    let t = DispatchSource.makeTimerSource(queue: .global())
    t.schedule(deadline: .now() + 5, repeating: 5)
    t.setEventHandler { [weak self] in self?.check() }
    t.resume()
    timer = t
  }

  private func check() {
    let conn = NWConnection(host: .init(host), port: .init(integerLiteral: UInt16(port)), using: .tcp)
    var done = false
    conn.stateUpdateHandler = { [weak self] state in
      guard let self, !done else { return }
      switch state {
      case .ready: done = true; self.misses = 0; conn.cancel()
      case .failed, .waiting: done = true; self.miss(); conn.cancel()
      default: break
      }
    }
    conn.start(queue: .global())
    DispatchQueue.global().asyncAfter(deadline: .now() + 3) { [weak self] in
      if !done { done = true; self?.miss(); conn.cancel() }
    }
  }

  private func miss() {
    misses += 1
    if misses >= 3 {
      timer?.cancel()
      cancelTunnelWithError(nil)
    }
  }
}
