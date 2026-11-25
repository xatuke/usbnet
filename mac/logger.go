package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"
)

const maxBodyLog = 64 * 1024

type interceptLogger struct {
	mu   sync.Mutex
	file *os.File
}

func newInterceptLogger(dir string) (*interceptLogger, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "intercept.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &interceptLogger{file: f}, nil
}

type logEntry struct {
	Time            string            `json:"time"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Status          int               `json:"status"`
	RequestHeaders  map[string]string `json:"request_headers"`
	ResponseHeaders map[string]string `json:"response_headers"`
	RequestBody     string            `json:"request_body,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`
	TLS             *tlsInfo          `json:"tls,omitempty"`
}

type tlsInfo struct {
	ServerName string `json:"server_name"`
	Version    string `json:"version"`
}

func (l *interceptLogger) logRequest(method, url string, status int, reqHeaders, respHeaders http.Header, reqBody, respBody []byte, tlsState *tls.ConnectionState) {
	log.Printf("MITM %s %s → %d", method, url, status)
	e := logEntry{
		Time:            time.Now().UTC().Format(time.RFC3339),
		Method:          method,
		URL:             url,
		Status:          status,
		RequestHeaders:  flattenHeaders(reqHeaders),
		ResponseHeaders: flattenHeaders(respHeaders),
		RequestBody:     encodeBody(reqBody),
		ResponseBody:    encodeBody(respBody),
	}
	if tlsState != nil {
		e.TLS = &tlsInfo{ServerName: tlsState.ServerName, Version: tlsVersionString(tlsState.Version)}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = json.NewEncoder(l.file).Encode(e)
}

func flattenHeaders(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, vs := range h {
		m[k] = vs[0]
		for _, v := range vs[1:] {
			m[k] += ", " + v
		}
	}
	return m
}

func encodeBody(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if len(b) > maxBodyLog {
		b = b[:maxBodyLog]
	}
	if utf8.Valid(b) {
		return string(b)
	}
	return "base64:" + base64.StdEncoding.EncodeToString(b)
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}
