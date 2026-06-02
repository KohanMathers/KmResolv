package cache

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/kohanmathers/kmresolv/internal/config"
	"github.com/kohanmathers/kmresolv/internal/dns"
	"github.com/kohanmathers/kmresolv/internal/logger"
)

type PrefetchFn func(name string, qtype uint16) (*dns.Message, error)

type cacheKey struct {
	name  string
	qtype uint16
}

type cacheEntry struct {
	msg         *dns.Message
	expires     time.Time
	cached      time.Time
	prefetching atomic.Bool
}

type negEntry struct {
	expires time.Time
}

const numShards = 64

type cacheShard struct {
	mu       sync.RWMutex
	entries  map[cacheKey]*cacheEntry
	negative map[cacheKey]negEntry
}

type Cache struct {
	shards      [numShards]cacheShard
	prefetchFn  PrefetchFn
	minTTL      uint32
	maxPerShard int
}

func (c *Cache) SetMinTTL(n uint32) {
	c.minTTL = n
}

func (c *Cache) SetMaxSize(n int) {
	if n > 0 {
		c.maxPerShard = (n + numShards - 1) / numShards
	} else {
		c.maxPerShard = 0
	}
}

func shardIdx(k cacheKey) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(k.name); i++ {
		h ^= uint32(k.name[i])
		h *= 16777619
	}
	h ^= uint32(k.qtype)
	h *= 16777619
	return h & (numShards - 1)
}

func (c *Cache) shard(k cacheKey) *cacheShard {
	return &c.shards[shardIdx(k)]
}

func NewCache() *Cache {
	c := &Cache{}
	for i := range c.shards {
		c.shards[i].entries = make(map[cacheKey]*cacheEntry)
		c.shards[i].negative = make(map[cacheKey]negEntry)
	}
	go c.evictLoop()
	return c
}

func (c *Cache) SetPrefetchFn(fn PrefetchFn) {
	c.prefetchFn = fn
}

func (c *Cache) SetNegative(name string, qtype uint16, ttl int) {
	if ttl == 0 {
		ttl = 300
	}
	k := cacheKey{name, qtype}
	s := c.shard(k)
	s.mu.Lock()
	s.negative[k] = negEntry{expires: time.Now().Add(time.Duration(ttl) * time.Second)}
	s.mu.Unlock()
	logger.LogDebug("cache negative: %s TTL=%ds", name, ttl)
}

func (c *Cache) IsNegative(name string, qtype uint16) bool {
	k := cacheKey{name, qtype}
	s := c.shard(k)
	s.mu.RLock()
	e, ok := s.negative[k]
	s.mu.RUnlock()
	return ok && time.Now().Before(e.expires)
}

func (c *Cache) Get(name string, qtype uint16, cfg *config.Config) *dns.Message {
	k := cacheKey{name, qtype}
	s := c.shard(k)
	s.mu.RLock()
	e, ok := s.entries[k]
	s.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return nil
	}

	if cfg.Resolver.Cache.Prefetch && c.prefetchFn != nil {
		total := e.expires.Sub(e.cached)
		remaining := time.Until(e.expires)
		if remaining < total/10 && e.prefetching.CompareAndSwap(false, true) {
			pf := c.prefetchFn
			go func() {
				defer e.prefetching.Store(false)
				logger.LogDebug("prefetching: %s", name)
				if msg, err := pf(name, qtype); err == nil {
					c.Set(name, qtype, msg)
				}
			}()
		}
	}

	elapsed := uint32(time.Since(e.cached).Seconds())
	return cloneMessageWithDecrementedTTL(e.msg, elapsed)
}

func cloneMessageWithDecrementedTTL(msg *dns.Message, elapsed uint32) *dns.Message {
	clone := *msg
	if elapsed == 0 {
		return &clone
	}
	clone.Answers = decrementRRs(msg.Answers, elapsed)
	clone.Authority = decrementRRs(msg.Authority, elapsed)
	clone.Additional = decrementRRs(msg.Additional, elapsed)
	return &clone
}

func decrementRRs(rrs []dns.RR, elapsed uint32) []dns.RR {
	out := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		if rr.TTL > elapsed {
			rr.TTL -= elapsed
		} else {
			rr.TTL = 0
		}
		out[i] = rr
	}
	return out
}

func (c *Cache) Set(name string, qtype uint16, msg *dns.Message) {
	ttl := lowestTTL(msg)
	if ttl == 0 {
		return
	}
	if c.minTTL > 0 && ttl < c.minTTL {
		ttl = c.minTTL
	}
	now := time.Now()
	k := cacheKey{name, qtype}
	s := c.shard(k)
	s.mu.Lock()
	if c.maxPerShard > 0 && len(s.entries) >= c.maxPerShard {
		if _, exists := s.entries[k]; !exists {
			var evictKey cacheKey
			var earliest time.Time
			for ek, ee := range s.entries {
				if earliest.IsZero() || ee.expires.Before(earliest) {
					earliest = ee.expires
					evictKey = ek
				}
			}
			delete(s.entries, evictKey)
		}
	}
	s.entries[k] = &cacheEntry{
		msg:     msg,
		expires: now.Add(time.Duration(ttl) * time.Second),
		cached:  now,
	}
	s.mu.Unlock()
}

func lowestTTL(msg *dns.Message) uint32 {
	var min uint32 = ^uint32(0)
	for _, rr := range msg.Answers {
		if rr.TTL < min {
			min = rr.TTL
		}
	}
	if min == ^uint32(0) {
		return 0
	}
	return min
}

const evictBatch = 64

func (c *Cache) evictLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		for i := range c.shards {
			c.evictShard(&c.shards[i], now)
		}
	}
}

func (c *Cache) evictShard(s *cacheShard, now time.Time) {
	s.mu.RLock()
	var deadEntries, deadNeg []cacheKey
	for k, e := range s.entries {
		if now.After(e.expires) {
			deadEntries = append(deadEntries, k)
		}
	}
	for k, e := range s.negative {
		if now.After(e.expires) {
			deadNeg = append(deadNeg, k)
		}
	}
	s.mu.RUnlock()

	for i := 0; i < len(deadEntries); i += evictBatch {
		end := min(i+evictBatch, len(deadEntries))
		s.mu.Lock()
		for _, k := range deadEntries[i:end] {
			if e, ok := s.entries[k]; ok && now.After(e.expires) {
				delete(s.entries, k)
			}
		}
		s.mu.Unlock()
	}
	for i := 0; i < len(deadNeg); i += evictBatch {
		end := min(i+evictBatch, len(deadNeg))
		s.mu.Lock()
		for _, k := range deadNeg[i:end] {
			if e, ok := s.negative[k]; ok && now.After(e.expires) {
				delete(s.negative, k)
			}
		}
		s.mu.Unlock()
	}
}

func (c *Cache) Size() int {
	var total int
	for i := range c.shards {
		c.shards[i].mu.RLock()
		total += len(c.shards[i].entries)
		c.shards[i].mu.RUnlock()
	}
	return total
}

func (c *Cache) NegativeSize() int {
	var total int
	for i := range c.shards {
		c.shards[i].mu.RLock()
		total += len(c.shards[i].negative)
		c.shards[i].mu.RUnlock()
	}
	return total
}

func (c *Cache) Flush(mode string) {
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		switch mode {
		case "negative":
			s.negative = make(map[cacheKey]negEntry)
		case "expired":
			now := time.Now()
			for k, e := range s.entries {
				if now.After(e.expires) {
					delete(s.entries, k)
				}
			}
			for k, e := range s.negative {
				if now.After(e.expires) {
					delete(s.negative, k)
				}
			}
		default:
			s.entries = make(map[cacheKey]*cacheEntry)
			s.negative = make(map[cacheKey]negEntry)
		}
		s.mu.Unlock()
	}
	logger.LogInfo("cache flushed: mode=%s", mode)
}
