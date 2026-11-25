package main

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type interceptedRequest struct {
	ID              uint64            `json:"id"`
	Time            time.Time         `json:"time"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Host            string            `json:"host"`
	Status          int               `json:"status"`
	RequestHeaders  http.Header       `json:"request_headers"`
	ResponseHeaders http.Header       `json:"response_headers"`
	RequestBody     []byte            `json:"request_body"`
	ResponseBody    []byte            `json:"response_body"`
	TLS             bool              `json:"tls"`
	TLSServerName   string            `json:"tls_server_name,omitempty"`
	DurationMS      int64             `json:"duration_ms"`
	Error           string            `json:"error,omitempty"`
}

type requestStore struct {
	mu        sync.RWMutex
	requests  []*interceptedRequest
	nextID    atomic.Uint64
	listeners []chan *interceptedRequest
	listenerMu sync.Mutex
}

func newRequestStore() *requestStore {
	return &requestStore{}
}

func (s *requestStore) add(r *interceptedRequest) {
	r.ID = s.nextID.Add(1)
	s.mu.Lock()
	s.requests = append(s.requests, r)
	// Cap at 10k entries in memory.
	if len(s.requests) > 10000 {
		s.requests = s.requests[len(s.requests)-10000:]
	}
	s.mu.Unlock()

	s.listenerMu.Lock()
	for _, ch := range s.listeners {
		select {
		case ch <- r:
		default:
		}
	}
	s.listenerMu.Unlock()
}

func (s *requestStore) subscribe() chan *interceptedRequest {
	ch := make(chan *interceptedRequest, 64)
	s.listenerMu.Lock()
	s.listeners = append(s.listeners, ch)
	s.listenerMu.Unlock()
	return ch
}

func (s *requestStore) unsubscribe(ch chan *interceptedRequest) {
	s.listenerMu.Lock()
	for i, c := range s.listeners {
		if c == ch {
			s.listeners = append(s.listeners[:i], s.listeners[i+1:]...)
			break
		}
	}
	s.listenerMu.Unlock()
	close(ch)
}

func (s *requestStore) list(host, method string, sinceID uint64, limit int) []*interceptedRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	var out []*interceptedRequest
	for _, r := range s.requests {
		if r.ID <= sinceID {
			continue
		}
		if host != "" && r.Host != host {
			continue
		}
		if method != "" && r.Method != method {
			continue
		}
		out = append(out, r)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (s *requestStore) get(id uint64) *interceptedRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.requests {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func (s *requestStore) count() int {
	s.mu.RLock()
	n := len(s.requests)
	s.mu.RUnlock()
	return n
}

func (s *requestStore) clear() {
	s.mu.Lock()
	s.requests = nil
	s.mu.Unlock()
}
