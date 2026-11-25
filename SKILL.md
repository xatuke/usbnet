# usbnet

Share a Mac's internet with an iPhone over USB. Intercept HTTPS traffic.

Repository: `~/usbnet` — [github.com/xatuke/usbnet](https://github.com/xatuke/usbnet)
Author: Aayushman Choudhary <aayushmanchaudhory@gmail.com>

## What it does

The Mac runs an HTTP/HTTPS proxy on the USB link-local address (169.254.x.x).
The iPhone finds it with Bonjour and routes all web traffic through it.
In MITM mode, the proxy forges TLS certificates to decrypt HTTPS traffic.

## Architecture

```
iPhone ──USB──> Mac (169.254.x.x:8888)
                 ├── proxy (plain or MITM)
                 ├── Bonjour advertisement (_usbnet._tcp)
                 └── REST API (/__usbnet/*)
```

**Mac side** (`mac/`): Go, stdlib only. No external dependencies.
- `main.go` — entry point, CLI flags, link polling, signal handling
- `certgen.go` — CA generation, per-host TLS certificate forging (RSA 2048, sync.Map cache)
- `mitm.go` — MITM handler: CONNECT hijack, TLS handshake, HTTP request forwarding
- `store.go` — in-memory request store with pub/sub (capped at 10k entries)
- `api.go` — JSON REST API for AI agents (status, list, detail, SSE stream, clear)
- `logger.go` — JSONL file logger at `~/.usbnet/logs/intercept.jsonl`
- `pinbypass.go` — Frida-based certificate pinning bypass script (needs jailbreak)
- `Launcher.swift` — macOS menu bar app that starts the Go binary

**iPhone side** (`ios/`): Swift, SwiftUI.
- `USBNetApp.swift` — UI: Bonjour discovery, manual address entry, VPN connect/disconnect, CA cert install button
- `PacketTunnelProvider.swift` — NE tunnel that sets a system-wide HTTP/HTTPS proxy, health-checks the USB link

Bundle ID: `com.ndtv.ndtvshopping.devtether.usbnet` (needs change to personal account)

## Commands

### Build and run (Mac)

```bash
cd ~/usbnet/mac
go build -o usbnet .
```

Standard proxy (no interception):
```bash
./usbnet run
```

MITM mode (intercepts HTTPS):
```bash
./usbnet run -mitm
```

The CA certificate is at `~/.usbnet/ca.pem` and `~/.usbnet/ca-key.pem`.
The first run creates them automatically.

### CLI reference

```
usbnet run [-port 8888] [-mitm] [-mitm-dir ~/.usbnet] [-skip en0] [-name "My Mac"] [-log default]
usbnet status                    # show USB link-local addresses
usbnet pinbypass                 # list running iOS apps (needs Frida + jailbreak)
usbnet pinbypass <app-name>      # bypass cert pinning on that app
usbnet pinbypass --script-only   # print the Frida JS script to stdout
```

### Build the iOS app

Open `ios/USBNet.xcodeproj` in Xcode. Select your signing team. Build to device.

## MITM API

All endpoints return JSON. Designed for AI agents, not browsers.

| Method | Path | Does |
|--------|------|------|
| GET | `/__usbnet/status` | MITM flag, request count, CA fingerprint |
| GET | `/__usbnet/requests?host=&method=&since_id=&limit=100` | Filtered list (no bodies) |
| GET | `/__usbnet/requests/{id}` | Full detail with base64 request/response bodies |
| GET | `/__usbnet/requests/stream` | SSE stream, supports `Last-Event-ID` reconnect |
| DELETE | `/__usbnet/requests` | Clear the store |
| GET | `/__usbnet/ca.pem` | CA certificate (PEM) |
| GET | `/__usbnet/ca.der` | CA certificate (DER) |
| GET | `/ca.pem` | CA certificate (direct, for iPhone install) |
| GET | `/ca.der` | CA certificate (direct, for iPhone install) |

### Request object (list)

```json
{
  "id": 405,
  "time": "2026-11-25T15:58:14.323Z",
  "method": "GET",
  "url": "https://www.google.com/search?q=...",
  "host": "www.google.com",
  "status": 200,
  "request_headers": {},
  "response_headers": {},
  "has_request_body": false,
  "has_response_body": true,
  "tls": true,
  "tls_server_name": "www.google.com",
  "duration_ms": 510
}
```

### Request object (detail)

Same fields, plus `request_body` and `response_body` as base64 strings.

## iPhone setup for MITM

1. Connect the iPhone to the Mac with a USB cable.
2. Start `usbnet run -mitm` on the Mac.
3. Open USB Net on the iPhone. Tap the Mac name to connect.
4. Tap "Install CA Certificate for MITM". Safari opens to download the profile.
5. Go to Settings > General > VPN & Device Management. Install the profile.
6. Go to Settings > General > About > Certificate Trust Settings. Enable full trust for "USB Net CA".

All HTTPS traffic is now intercepted. Query `/__usbnet/requests` to inspect it.

## Certificate pinning

Apps that pin certificates reject the forged cert. The TLS handshake fails with EOF.
These show as errors in the request store.

`usbnet pinbypass <app-name>` injects a Frida script that hooks:
- Security.framework (SecTrustEvaluateWithError, SecTrustEvaluate, SSLHandshake)
- NSURLSession delegates (session-level and task-level)
- Network.framework (sec_protocol_options_set_verify_block, nw_tls_create_peer_trust)
- AFNetworking, Alamofire (5 evaluator classes + ServerTrustManager)
- TrustKit, WKWebView, BoringSSL

Requires: Frida on PATH, a jailbroken iPhone with frida-server, or a repackaged app with Frida Gadget.

## Data locations

| Path | Contents |
|------|----------|
| `~/.usbnet/ca.pem` | CA certificate |
| `~/.usbnet/ca-key.pem` | CA private key |
| `~/.usbnet/logs/intercept.jsonl` | JSONL log of all intercepted requests |

## Typical agent workflow

```bash
# 1. Start MITM proxy
cd ~/usbnet/mac && go build -o usbnet . && ./usbnet run -mitm

# 2. Connect iPhone (user does this in the app)

# 3. Check status
curl -s http://169.254.x.x:8888/__usbnet/status

# 4. Watch traffic in real time
curl -s http://169.254.x.x:8888/__usbnet/requests/stream

# 5. Query specific host
curl -s 'http://169.254.x.x:8888/__usbnet/requests?host=api.example.com'

# 6. Get full request with bodies
curl -s http://169.254.x.x:8888/__usbnet/requests/42

# 7. Decode a response body
curl -s http://169.254.x.x:8888/__usbnet/requests/42 | python3 -c "
import json,sys,base64
r = json.load(sys.stdin)
print(base64.b64decode(r['response_body']).decode('utf-8', errors='replace')[:2000])
"
```

Replace `169.254.x.x` with the actual link-local address. Run `usbnet status` to find it.
