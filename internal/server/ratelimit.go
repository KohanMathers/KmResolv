package server

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/kohanmathers/kmresolv/internal/config"
)

type aclRule struct {
	ipNet *net.IPNet
	allow bool
}

type compiledACL struct {
	rules        []aclRule
	defaultAllow bool
}

func newCompiledACL(cfg config.ACLConfig) *compiledACL {
	a := &compiledACL{defaultAllow: strings.ToLower(cfg.Default) != "deny"}
	for _, r := range cfg.Rules {
		_, ipNet, err := net.ParseCIDR(r.Subnet)
		if err != nil {
			continue
		}
		a.rules = append(a.rules, aclRule{ipNet: ipNet, allow: strings.ToLower(r.Action) == "allow"})
	}
	return a
}

func (a *compiledACL) allowed(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return a.defaultAllow
	}
	for _, r := range a.rules {
		if r.ipNet.Contains(ip) {
			return r.allow
		}
	}
	return a.defaultAllow
}

const rateLimitIdleTTL = 10 * time.Minute

type tokenBucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

type rateLimiter struct {
	mu          sync.Mutex
	buckets     map[string]*tokenBucket
	rate        float64
	burst       float64
	nextCleanup time.Time
}

func newRateLimiter(qps, burst int) *rateLimiter {
	return &rateLimiter{
		buckets: make(map[string]*tokenBucket),
		rate:    float64(qps),
		burst:   float64(burst),
	}
}

func (r *rateLimiter) allow(ip string) bool {
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.nextCleanup.IsZero() {
		r.nextCleanup = now.Add(time.Minute)
	} else if now.After(r.nextCleanup) {
		r.cleanup(now)
		r.nextCleanup = now.Add(time.Minute)
	}

	b := r.buckets[ip]
	if b == nil {
		b = &tokenBucket{tokens: r.burst, last: now}
		r.buckets[ip] = b
	}

	elapsed := now.Sub(b.last).Seconds()
	b.tokens = min(r.burst, b.tokens+elapsed*r.rate)
	b.last = now
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (r *rateLimiter) cleanup(now time.Time) {
	for ip, b := range r.buckets {
		if now.Sub(b.lastSeen) > rateLimitIdleTTL {
			delete(r.buckets, ip)
		}
	}
}

func sourceIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP.String()
	case *net.TCPAddr:
		return a.IP.String()
	case *net.IPAddr:
		return a.IP.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return host
	}
	return addr.String()
}
