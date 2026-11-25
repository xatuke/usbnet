package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type apiHandler struct {
	store *requestStore
	caPEM []byte
}

func (a *apiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case path == "/__usbnet/status" && r.Method == http.MethodGet:
		a.status(w)
	case path == "/__usbnet/requests/stream" && r.Method == http.MethodGet:
		a.streamRequests(w, r)
	case path == "/__usbnet/requests" && r.Method == http.MethodGet:
		a.listRequests(w, r)
	case path == "/__usbnet/requests" && r.Method == http.MethodDelete:
		a.clearRequests(w)
	case strings.HasPrefix(path, "/__usbnet/requests/") && r.Method == http.MethodGet:
		a.getRequest(w, r)
	case path == "/__usbnet/ca.pem" && r.Method == http.MethodGet:
		a.serveCAPEM(w)
	case path == "/__usbnet/ca.der" && r.Method == http.MethodGet:
		a.serveCADER(w)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (a *apiHandler) status(w http.ResponseWriter) {
	fp := sha256.Sum256(a.caPEM)
	writeJSON(w, http.StatusOK, map[string]any{
		"mitm":           true,
		"requests_count": a.store.count(),
		"ca_fingerprint": "sha256:" + fmt.Sprintf("%x", fp),
	})
}

type requestSummary struct {
	ID              uint64      `json:"id"`
	Time            string      `json:"time"`
	Method          string      `json:"method"`
	URL             string      `json:"url"`
	Host            string      `json:"host"`
	Status          int         `json:"status"`
	RequestHeaders  http.Header `json:"request_headers"`
	ResponseHeaders http.Header `json:"response_headers"`
	HasRequestBody  bool        `json:"has_request_body"`
	HasResponseBody bool        `json:"has_response_body"`
	TLS             bool        `json:"tls"`
	TLSServerName   string      `json:"tls_server_name,omitempty"`
	DurationMS      int64       `json:"duration_ms"`
	Error           string      `json:"error,omitempty"`
}

func summarize(r *interceptedRequest) requestSummary {
	return requestSummary{
		ID:              r.ID,
		Time:            r.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		Method:          r.Method,
		URL:             r.URL,
		Host:            r.Host,
		Status:          r.Status,
		RequestHeaders:  r.RequestHeaders,
		ResponseHeaders: r.ResponseHeaders,
		HasRequestBody:  len(r.RequestBody) > 0,
		HasResponseBody: len(r.ResponseBody) > 0,
		TLS:             r.TLS,
		TLSServerName:   r.TLSServerName,
		DurationMS:      r.DurationMS,
		Error:           r.Error,
	}
}

type requestDetail struct {
	ID              uint64      `json:"id"`
	Time            string      `json:"time"`
	Method          string      `json:"method"`
	URL             string      `json:"url"`
	Host            string      `json:"host"`
	Status          int         `json:"status"`
	RequestHeaders  http.Header `json:"request_headers"`
	ResponseHeaders http.Header `json:"response_headers"`
	RequestBody     string      `json:"request_body"`
	ResponseBody    string      `json:"response_body"`
	TLS             bool        `json:"tls"`
	TLSServerName   string      `json:"tls_server_name,omitempty"`
	DurationMS      int64       `json:"duration_ms"`
	Error           string      `json:"error,omitempty"`
}

func detail(r *interceptedRequest) requestDetail {
	return requestDetail{
		ID:              r.ID,
		Time:            r.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		Method:          r.Method,
		URL:             r.URL,
		Host:            r.Host,
		Status:          r.Status,
		RequestHeaders:  r.RequestHeaders,
		ResponseHeaders: r.ResponseHeaders,
		RequestBody:     base64.StdEncoding.EncodeToString(r.RequestBody),
		ResponseBody:    base64.StdEncoding.EncodeToString(r.ResponseBody),
		TLS:             r.TLS,
		TLSServerName:   r.TLSServerName,
		DurationMS:      r.DurationMS,
		Error:           r.Error,
	}
}

func (a *apiHandler) listRequests(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host := q.Get("host")
	method := q.Get("method")
	sinceID, _ := strconv.ParseUint(q.Get("since_id"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 100
	}

	reqs := a.store.list(host, method, sinceID, limit)
	out := make([]requestSummary, len(reqs))
	for i, req := range reqs {
		out[i] = summarize(req)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *apiHandler) getRequest(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/__usbnet/requests/")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request id"})
		return
	}
	req := a.store.get(id)
	if req == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "request not found"})
		return
	}
	writeJSON(w, http.StatusOK, detail(req))
}

func (a *apiHandler) streamRequests(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming unsupported"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	if lastID := r.Header.Get("Last-Event-ID"); lastID != "" {
		if id, err := strconv.ParseUint(lastID, 10, 64); err == nil {
			for _, req := range a.store.list("", "", id, 1000) {
				data, _ := json.Marshal(summarize(req))
				fmt.Fprintf(w, "id: %d\ndata: %s\n\n", req.ID, data)
			}
			flusher.Flush()
		}
	}

	ch := a.store.subscribe()
	defer a.store.unsubscribe(ch)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(summarize(req))
			fmt.Fprintf(w, "id: %d\ndata: %s\n\n", req.ID, data)
			flusher.Flush()
		}
	}
}

func (a *apiHandler) clearRequests(w http.ResponseWriter) {
	a.store.clear()
	writeJSON(w, http.StatusOK, map[string]bool{"cleared": true})
}

func (a *apiHandler) serveCAPEM(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="USBNet-CA.pem"`)
	w.Write(a.caPEM)
}

func (a *apiHandler) serveCADER(w http.ResponseWriter) {
	block, _ := pem.Decode(a.caPEM)
	if block == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ca cert unavailable"})
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="USBNet-CA.der"`)
	w.Write(block.Bytes)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
