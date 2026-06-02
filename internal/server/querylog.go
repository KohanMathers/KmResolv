package server

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/kohanmathers/kmresolv/internal/logger"
)

type QueryEntry struct {
	Time    time.Time `json:"time"`
	Domain  string    `json:"domain"`
	Type    string    `json:"type"`
	Client  string    `json:"client"`
	Status  string    `json:"status"`
	Latency int64     `json:"latency_ms"`
}

type QueryLog struct {
	mu      sync.RWMutex
	entries []QueryEntry
	head    int
	count   int
	max     int
	file    *os.File
}

func newQueryLog(max int, filePath string) *QueryLog {
	l := &QueryLog{max: max, entries: make([]QueryEntry, max)}
	if filePath != "" {
		f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			logger.LogWarn("query log file: %v", err)
		} else {
			l.file = f
			logger.LogInfo("query log file: %s", filePath)
		}
	}
	return l
}

func (l *QueryLog) Add(e QueryEntry) {
	l.mu.Lock()
	l.entries[l.head] = e
	l.head = (l.head + 1) % l.max
	if l.count < l.max {
		l.count++
	}
	if l.file != nil {
		if line, err := json.Marshal(e); err == nil {
			l.file.Write(append(line, '\n'))
		}
	}
	l.mu.Unlock()
}

func (l *QueryLog) Recent(n int) []QueryEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if n > l.count {
		n = l.count
	}
	out := make([]QueryEntry, n)
	for i := range n {
		out[i] = l.entries[(l.head-n+i+l.max)%l.max]
	}
	return out
}
