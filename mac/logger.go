package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"
)

const maxBodyLog = 64 * 1024

type fileLogger struct {
	file *os.File
	mu   sync.Mutex
}

func newFileLogger(dir string) (*fileLogger, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "intercept.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &fileLogger{file: f}, nil
}

type logLine struct {
	ID              uint64            `json:"id"`
	Time            time.Time         `json:"time"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Host            string            `json:"host"`
	Status          int               `json:"status"`
	RequestHeaders  map[string]string `json:"request_headers"`
	ResponseHeaders map[string]string `json:"response_headers"`
	RequestBody     string            `json:"request_body,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`
	TLS             bool              `json:"tls"`
	TLSServerName   string            `json:"tls_server_name,omitempty"`
	DurationMS      int64             `json:"duration_ms"`
	Error           string            `json:"error,omitempty"`
}

func (fl *fileLogger) run(store *requestStore) {
	ch := store.subscribe()
	for r := range ch {
		line := logLine{
			ID:              r.ID,
			Time:            r.Time,
			Method:          r.Method,
			URL:             r.URL,
			Host:            r.Host,
			Status:          r.Status,
			RequestHeaders:  flattenHeaders(r.RequestHeaders),
			ResponseHeaders: flattenHeaders(r.ResponseHeaders),
			RequestBody:     encodeBody(r.RequestBody),
			ResponseBody:    encodeBody(r.ResponseBody),
			TLS:             r.TLS,
			TLSServerName:   r.TLSServerName,
			DurationMS:      r.DurationMS,
			Error:           r.Error,
		}
		fl.mu.Lock()
		_ = json.NewEncoder(fl.file).Encode(line)
		fl.mu.Unlock()
	}
}

func flattenHeaders(h map[string][]string) map[string]string {
	if h == nil {
		return nil
	}
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
