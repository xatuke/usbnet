// "USB Net" launcher. Registers the usbnet proxy as a login agent with SMAppService, so it starts at
// login and shows in System Settings → Login Items as "USB Net" with this app's icon.
//   Double-click the app       turn sharing on (or see status and turn it off)
//   USB Net install|uninstall|status   same, from Terminal
import AppKit
import ServiceManagement

let agent = SMAppService.agent(plistName: "io.github.xatuke.usbnet.plist")

func describe(_ s: SMAppService.Status) -> String {
  switch s {
  case .enabled: return "on: starts at login and runs in the background"
  case .requiresApproval: return "waiting for approval in System Settings → General → Login Items"
  case .notRegistered: return "off"
  case .notFound: return "not found (is the app in Applications?)"
  @unknown default: return "unknown"
  }
}

func install() throws { try agent.register() }
func uninstall() throws { try agent.unregister() }

let args = CommandLine.arguments.dropFirst()
if let cmd = args.first {
  do {
    switch cmd {
    case "install": try install(); print("USB Net: \(describe(agent.status))")
    case "uninstall": try uninstall(); print("USB Net: off")
    case "status": print("USB Net: \(describe(agent.status))")
    default: print("usage: USB Net install|uninstall|status"); exit(2)
    }
  } catch {
    fputs("USB Net: \(error.localizedDescription)\n", stderr); exit(1)
  }
  exit(0)
}

// Double-clicked: show a small dialog.
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
app.activate(ignoringOtherApps: true)
let alert = NSAlert()
alert.icon = NSApp.applicationIconImage
if agent.status == .enabled {
  alert.messageText = "USB Net is sharing this Mac's internet"
  alert.informativeText = "Plug in your iPhone, open USB Net on the phone and tap Connect. Sharing starts at login."
  alert.addButton(withTitle: "OK")
  alert.addButton(withTitle: "Turn Off")
  if alert.runModal() == .alertSecondButtonReturn { try? uninstall() }
} else {
  alert.messageText = "Share this Mac's internet with your iPhone over USB?"
  alert.informativeText = "USB Net runs in the background and starts at login. It only accepts connections from a phone on the USB cable."
  alert.addButton(withTitle: "Turn On")
  alert.addButton(withTitle: "Cancel")
  if alert.runModal() == .alertFirstButtonReturn {
    do {
      try install()
      if agent.status == .requiresApproval { SMAppService.openSystemSettingsLoginItems() }
    } catch {
      let e = NSAlert(); e.messageText = "Couldn't turn on USB Net"; e.informativeText = error.localizedDescription; e.runModal()
    }
  }
}
