package main

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type mitmHandler struct {
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
	store  *requestStore
	caPEM  []byte
	api    http.Handler
}

func (m *mitmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !fromLink(r.RemoteAddr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if r.URL.Host == "" {
		if m.api != nil && strings.HasPrefix(r.URL.Path, "/__usbnet/") {
			m.api.ServeHTTP(w, r)
			return
		}
		switch r.URL.Path {
		case "/ca.pem":
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Header().Set("Content-Disposition", `attachment; filename="USBNet-CA.pem"`)
			w.Write(m.caPEM)
		case "/ca.der":
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			w.Header().Set("Content-Disposition", `attachment; filename="USBNet-CA.der"`)
			w.Write(m.caCert.Raw)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"running","mitm":true}`))
		}
		return
	}

	if r.Method == http.MethodConnect {
		m.intercept(w, r)
		return
	}

	m.forwardHTTP(w, r)
}

func (m *mitmHandler) forwardHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	reqBody, _ := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	r.Body.Close()

	outReq, _ := http.NewRequest(r.Method, r.URL.String(), nil)
	outReq.Header = r.Header.Clone()
	for _, h := range hopByHop {
		outReq.Header.Del(h)
	}
	if len(reqBody) > 0 {
		outReq.Body = io.NopCloser(bytes.NewReader(reqBody))
		outReq.ContentLength = int64(len(reqBody))
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		m.store.add(&interceptedRequest{
			Time:           start,
			Method:         r.Method,
			URL:            r.URL.String(),
			Host:           r.URL.Hostname(),
			RequestHeaders: r.Header,
			RequestBody:    reqBody,
			Error:          err.Error(),
			DurationMS:     time.Since(start).Milliseconds(),
		})
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))

	m.store.add(&interceptedRequest{
		Time:            start,
		Method:          r.Method,
		URL:             r.URL.String(),
		Host:            r.URL.Hostname(),
		Status:          resp.StatusCode,
		RequestHeaders:  r.Header,
		ResponseHeaders: resp.Header,
		RequestBody:     reqBody,
		ResponseBody:    respBody,
		DurationMS:      time.Since(start).Milliseconds(),
	})

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func (m *mitmHandler) intercept(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		return
	}
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	cert, err := forgeCert(m.caCert, m.caKey, host)
	if err != nil {
		log.Printf("MITM forgeCert %s: %v", host, err)
		clientConn.Close()
		return
	}

	tlsClient := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	})
	tlsClient.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsClient.Handshake(); err != nil {
		log.Printf("MITM handshake %s: %v (cert pinning?)", host, err)
		m.store.add(&interceptedRequest{
			Time:          time.Now(),
			Method:        "CONNECT",
			URL:           "https://" + r.Host,
			Host:          host,
			TLS:           true,
			TLSServerName: host,
			Error:         "TLS handshake failed: " + err.Error(),
		})
		tlsClient.Close()
		return
	}
	tlsClient.SetDeadline(time.Time{})
	defer tlsClient.Close()

	upstream := &http.Transport{
		TLSClientConfig:     &tls.Config{ServerName: host},
		ForceAttemptHTTP2:   false,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	defer upstream.CloseIdleConnections()

	br := bufio.NewReader(prependBuffered(clientBuf, tlsClient))
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		req.URL.Scheme = "https"
		req.URL.Host = r.Host

		m.roundtrip(tlsClient, req, host, r.Host, upstream)
	}
}

func (m *mitmHandler) roundtrip(clientTLS *tls.Conn, req *http.Request, host, hostPort string, upstream *http.Transport) {
	start := time.Now()

	reqBody, _ := io.ReadAll(io.LimitReader(req.Body, 10<<20))
	req.Body.Close()

	outReq, _ := http.NewRequest(req.Method, req.URL.String(), nil)
	outReq.Header = req.Header.Clone()
	for _, h := range hopByHop {
		outReq.Header.Del(h)
	}
	if outReq.Header.Get("Host") == "" {
		outReq.Host = host
	}
	if len(reqBody) > 0 {
		outReq.Body = io.NopCloser(bytes.NewReader(reqBody))
		outReq.ContentLength = int64(len(reqBody))
	}

	resp, err := upstream.RoundTrip(outReq)
	if err != nil {
		writeHTTPError(clientTLS, 502, err.Error())
		m.store.add(&interceptedRequest{
			Time:           start,
			Method:         req.Method,
			URL:            req.URL.String(),
			Host:           host,
			RequestHeaders: req.Header,
			RequestBody:    reqBody,
			TLS:            true,
			TLSServerName:  host,
			Error:          err.Error(),
			DurationMS:     time.Since(start).Milliseconds(),
		})
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))

	m.store.add(&interceptedRequest{
		Time:            start,
		Method:          req.Method,
		URL:             req.URL.String(),
		Host:            host,
		Status:          resp.StatusCode,
		RequestHeaders:  req.Header,
		ResponseHeaders: resp.Header,
		RequestBody:     reqBody,
		ResponseBody:    respBody,
		TLS:             true,
		TLSServerName:   host,
		DurationMS:      time.Since(start).Milliseconds(),
	})

	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	resp.Header.Del("Transfer-Encoding")
	resp.Header.Set("Content-Length", fmt.Sprint(len(respBody)))
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
		}
	}
	sb.WriteString("\r\n")
	clientTLS.Write([]byte(sb.String()))
	clientTLS.Write(respBody)
}

func writeHTTPError(w io.Writer, code int, msg string) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
		code, http.StatusText(code), len(msg), msg)
}

func prependBuffered(buf *bufio.ReadWriter, r io.Reader) io.Reader {
	n := buf.Reader.Buffered()
	if n == 0 {
		return r
	}
	peeked, _ := buf.Reader.Peek(n)
	return io.MultiReader(bytes.NewReader(peeked), r)
}

var hopByHop = []string{"Proxy-Connection", "Proxy-Authorization", "Connection", "Keep-Alive", "Te", "Trailer", "Upgrade"}
