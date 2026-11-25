import Darwin
import NetworkExtension

/// Sets a phone-wide HTTP/HTTPS proxy that points at the Mac on the USB link. The tunnel itself
/// carries no packets. Every 5 s it checks that the USB link is still there; after 3 misses (cable
/// unplugged) it stops, so the phone goes back to its normal connection.
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

  /// The cable is present while the phone has an IPv4 link-local (169.254.x.x) address on an
  /// interface that is up. A socket probe to the Mac is not used: iOS blocks it from the extension
  /// (Local Network privacy), which made the tunnel stop by itself.
  private func check() {
    if usbLinkPresent() { misses = 0 } else { miss() }
  }

  private func usbLinkPresent() -> Bool {
    var list: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&list) == 0, let first = list else { return true }
    defer { freeifaddrs(list) }
    var p: UnsafeMutablePointer<ifaddrs>? = first
    while let ifa = p {
      defer { p = ifa.pointee.ifa_next }
      let flags = Int32(ifa.pointee.ifa_flags)
      guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0,
            let addr = ifa.pointee.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET) else { continue }
      let a = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
      if a >> 16 == 0xA9FE { return true }  // 169.254.0.0/16
    }
    return false
  }

  private func miss() {
    misses += 1
    if misses >= 3 {
      timer?.cancel()
      cancelTunnelWithError(nil)
    }
  }
}
