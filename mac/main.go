// usbnet: share this Mac's internet with an iPhone over the USB cable.
//
// When an iPhone is plugged in, macOS brings up a private IPv4 link-local network (169.254.0.0/16)
// over the cable. usbnet runs an HTTP/HTTPS proxy on the Mac's address on that link, accepts only
// clients from the link, and advertises itself over Bonjour (_usbnet._tcp) so the iOS app can find it.
// The address changes when the phone is re-plugged; usbnet notices and follows it.
package main

import (
	"context"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	serviceType = "_usbnet._tcp"
)

var linkLocal = &net.IPNet{IP: net.IPv4(169, 254, 0, 0), Mask: net.CIDRMask(16, 32)}

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		port := fs.Int("port", 8888, "proxy port")
		skip := fs.String("skip", "", "comma-separated interfaces to ignore (e.g. en0)")
		name := fs.String("name", "", "name shown on the iPhone (default: this Mac's computer name)")
		logTo := fs.String("log", "", `log file ("default" = ~/Library/Logs/usbnet.log)`)
		mitm := fs.Bool("mitm", false, "enable MITM interception of HTTPS traffic")
		mitmDir := fs.String("mitm-dir", "", `directory for CA certs and logs (default: ~/.usbnet)`)
		_ = fs.Parse(os.Args[2:])
		if *logTo != "" {
			if *logTo == "default" {
				home, _ := os.UserHomeDir()
				*logTo = filepath.Join(home, "Library", "Logs", "usbnet.log")
			}
			if f, err := os.OpenFile(*logTo, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
				log.SetOutput(f)
			}
		}
		if *mitm {
			if *mitmDir == "" {
				home, _ := os.UserHomeDir()
				*mitmDir = filepath.Join(home, ".usbnet")
			}
			runMITM(*port, splitList(*skip), *name, *mitmDir)
		} else {
			run(*port, splitList(*skip), *name)
		}
	case "status":
		status()
	case "pinbypass":
		pinbypass(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usbnet: share this Mac's internet with an iPhone over USB

  usbnet run [-port 8888]       run the proxy (the USB Net app starts this in the background)
  usbnet run -mitm              run with HTTPS interception (MITM mode)
  usbnet status                 show the USB links usbnet would use
  usbnet pinbypass [app-name]   bypass certificate pinning on an iOS app via Frida`)
}

func splitList(s string) map[string]bool {
	m := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			m[p] = true
		}
	}
	return m
}

// usbLinks returns interface name → this Mac's IPv4 link-local address, for interfaces that look like a
// device-over-USB link: up, running, not loopback/Wi-Fi/peer-to-peer, with a 169.254.x.x address.
func usbLinks(skip map[string]bool) map[string]net.IP {
	out := map[string]net.IP{}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, i := range ifs {
		if skip[i.Name] || i.Flags&net.FlagUp == 0 || i.Flags&net.FlagRunning == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		if strings.HasPrefix(i.Name, "awdl") || strings.HasPrefix(i.Name, "llw") || strings.HasPrefix(i.Name, "utun") || strings.HasPrefix(i.Name, "bridge") {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && linkLocal.Contains(n.IP) {
				out[i.Name] = n.IP.To4()
				break
			}
		}
	}
	return out
}

func status() {
	links := usbLinks(nil)
	if len(links) == 0 {
		fmt.Println("No USB link found. Plug the iPhone in, unlock it and tap Trust.")
		return
	}
	for name, ip := range links {
		fmt.Printf("%s  %s\n", name, ip)
	}
}

// listener is one proxy + Bonjour advertisement bound to one link address.
type listener struct {
	ip     string
	srv    *http.Server
	advert *exec.Cmd
}

func run(port int, skip map[string]bool, name string) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	host := name
	if host == "" {
		if out, err := exec.Command("/usr/sbin/scutil", "--get", "ComputerName").Output(); err == nil {
			host = strings.TrimSpace(string(out))
		}
	}
	if host == "" {
		host, _ = os.Hostname()
		host = strings.TrimSuffix(host, ".local")
	}

	active := map[string]*listener{} // key: interface name
	var mu sync.Mutex
	sync1 := func() {
		mu.Lock()
		defer mu.Unlock()
		want := usbLinks(skip)
		for name, l := range active {
			if ip, ok := want[name]; !ok || ip.String() != l.ip {
				log.Printf("%s: link gone or changed (%s), stopping", name, l.ip)
				l.close()
				delete(active, name)
			}
		}
		for name, ip := range want {
			if _, ok := active[name]; ok {
				continue
			}
			l, err := start(name, ip.String(), port, host)
			if err != nil {
				log.Printf("%s: %v", name, err)
				continue
			}
			active[name] = l
		}
	}
	log.Printf("usbnet: watching for iPhone USB links (proxy port %d)", port)
	sync1()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			mu.Lock()
			for _, l := range active {
				l.close()
			}
			mu.Unlock()
			log.Print("usbnet: stopped")
			return
		case <-t.C:
			sync1()
		}
	}
}

func runMITM(port int, skip map[string]bool, name, mitmDir string) {
	caPair, caCert, err := loadOrCreateCA(mitmDir)
	if err != nil {
		log.Fatalf("CA init: %v", err)
	}
	caKey := caPair.PrivateKey.(*rsa.PrivateKey)
	caPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	log.Printf("MITM CA: %s/ca.pem", mitmDir)

	store := newRequestStore()

	fl, err := newFileLogger(filepath.Join(mitmDir, "logs"))
	if err != nil {
		log.Fatalf("logger: %v", err)
	}
	go fl.run(store)

	api := &apiHandler{store: store, caPEM: caPEMBlock}
	handler := &mitmHandler{
		caCert: caCert,
		caKey:  caKey,
		store:  store,
		caPEM:  caPEMBlock,
		api:    api,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	host := name
	if host == "" {
		if out, err := exec.Command("/usr/sbin/scutil", "--get", "ComputerName").Output(); err == nil {
			host = strings.TrimSpace(string(out))
		}
	}
	if host == "" {
		host, _ = os.Hostname()
		host = strings.TrimSuffix(host, ".local")
	}

	active := map[string]*listener{}
	var mu sync.Mutex
	sync1 := func() {
		mu.Lock()
		defer mu.Unlock()
		want := usbLinks(skip)
		for name, l := range active {
			if ip, ok := want[name]; !ok || ip.String() != l.ip {
				log.Printf("%s: link gone or changed (%s), stopping", name, l.ip)
				l.close()
				delete(active, name)
			}
		}
		for name, ip := range want {
			if _, ok := active[name]; ok {
				continue
			}
			l, err := startWithHandler(name, ip.String(), port, host, handler)
			if err != nil {
				log.Printf("%s: %v", name, err)
				continue
			}
			active[name] = l
		}
	}
	log.Printf("usbnet: MITM mode, watching for iPhone USB links (proxy port %d)", port)
	log.Printf("usbnet: API at http://<link-ip>:%d/__usbnet/status", port)
	sync1()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			mu.Lock()
			for _, l := range active {
				l.close()
			}
			mu.Unlock()
			log.Print("usbnet: stopped")
			return
		case <-t.C:
			sync1()
		}
	}
}

func startWithHandler(iface, ip string, port int, host string, handler http.Handler) (*listener, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, ifi.Index)
		}); err != nil {
			return err
		}
		return serr
	}}
	ln, err := lc.Listen(context.Background(), "tcp4", net.JoinHostPort(ip, fmt.Sprint(port)))
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 30 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("%s: %v", iface, err)
		}
	}()
	adv := exec.Command("/usr/bin/dns-sd", "-R", host, serviceType, "local", fmt.Sprint(port), "addr="+ip, fmt.Sprintf("port=%d", port))
	if err := adv.Start(); err != nil {
		log.Printf("%s: bonjour advertise failed: %v", iface, err)
		adv = nil
	}
	log.Printf("%s: MITM proxy at %s:%d", iface, ip, port)
	return &listener{ip: ip, srv: srv, advert: adv}, nil
}

func start(iface, ip string, port int, host string) (*listener, error) {
	// Bind the socket to the USB interface (IP_BOUND_IF). The Mac can have more than one route to
	// 169.254.0.0/16 (for example on Wi-Fi), and without this the replies to the phone can leave on
	// the wrong interface. Accepted connections inherit the binding.
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, ifi.Index)
		}); err != nil {
			return err
		}
		return serr
	}}
	ln, err := lc.Listen(context.Background(), "tcp4", net.JoinHostPort(ip, fmt.Sprint(port)))
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: proxyHandler{}, ReadHeaderTimeout: 30 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("%s: %v", iface, err)
		}
	}()
	// Advertise with the built-in mDNSResponder. The TXT record carries the address so the phone
	// doesn't need to resolve it; the app only uses addresses on the 169.254/16 link.
	// One advertisement per link; the instance name is what the iPhone shows.
	adv := exec.Command("/usr/bin/dns-sd", "-R", host, serviceType, "local", fmt.Sprint(port), "addr="+ip, fmt.Sprintf("port=%d", port))
	if err := adv.Start(); err != nil {
		log.Printf("%s: bonjour advertise failed: %v", iface, err)
		adv = nil
	}
	log.Printf("%s: sharing internet at %s:%d", iface, ip, port)
	return &listener{ip: ip, srv: srv, advert: adv}, nil
}

func (l *listener) close() {
	if l.advert != nil && l.advert.Process != nil {
		_ = l.advert.Process.Kill()
		_ = l.advert.Wait()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = l.srv.Shutdown(ctx)
}

// proxyHandler is a minimal forward proxy: CONNECT for HTTPS, absolute-URI requests for plain HTTP.
type proxyHandler struct{}

var transport = &http.Transport{Proxy: nil, ForceAttemptHTTP2: false, MaxIdleConnsPerHost: 16, IdleConnTimeout: 90 * time.Second}

func (proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !fromLink(r.RemoteAddr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodConnect {
		tunnel(w, r)
		return
	}
	if r.URL.Host == "" {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "usbnet is running")
		return
	}
	r.RequestURI = ""
	for _, h := range []string{"Proxy-Connection", "Proxy-Authorization", "Connection", "Keep-Alive", "Te", "Trailer", "Upgrade"} {
		r.Header.Del(h)
	}
	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func fromLink(remote string) bool {
	h, _, err := net.SplitHostPort(remote)
	ip := net.ParseIP(h)
	return err == nil && ip != nil && linkLocal.Contains(ip)
}

func tunnel(w http.ResponseWriter, r *http.Request) {
	up, err := net.DialTimeout("tcp", r.Host, 15*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	down, buf, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	_, _ = down.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go func() {
		// Bytes the client already sent after the CONNECT headers.
		if n := buf.Reader.Buffered(); n > 0 {
			b, _ := buf.Reader.Peek(n)
			_, _ = up.Write(b)
		}
		_, _ = io.Copy(up, down)
		_ = up.(*net.TCPConn).CloseWrite()
	}()
	_, _ = io.Copy(down, up)
	down.Close()
	up.Close()
}
