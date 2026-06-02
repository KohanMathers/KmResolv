package server

import "sync"

const historyWindow = 300

type HistoryBucket struct {
	Queries uint64 `json:"queries"`
	Hits    uint64 `json:"hits"`
	Blocked uint64 `json:"blocked"`
}

type statsHistory struct {
	mu      sync.RWMutex
	buckets [historyWindow]HistoryBucket
	head    int
}

func (h *statsHistory) record(b HistoryBucket) {
	h.mu.Lock()
	h.buckets[h.head] = b
	h.head = (h.head + 1) % historyWindow
	h.mu.Unlock()
}

func (h *statsHistory) snapshot() []HistoryBucket {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]HistoryBucket, historyWindow)
	for i := range historyWindow {
		out[i] = h.buckets[(h.head+i)%historyWindow]
	}
	return out
}
