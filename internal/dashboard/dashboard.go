package dashboard

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kohanmathers/kmresolv/internal/config"
	"github.com/kohanmathers/kmresolv/internal/logger"
	"github.com/kohanmathers/kmresolv/internal/server"
	"github.com/kohanmathers/kmresolv/internal/updater"
)

//go:embed dashboard.html
var dashboardHTML []byte

//go:embed login.html
var loginHTML []byte

type nonceStore struct {
	mu     sync.Mutex
	nonces map[string]time.Time
}

var sessionSecret []byte
var sessionToken string
var nonces = &nonceStore{nonces: make(map[string]time.Time)}

func init() {
	sessionSecret = make([]byte, 32)
	rand.Read(sessionSecret)
	b := make([]byte, 32)
	rand.Read(b)
	sessionToken = hex.EncodeToString(b)
}

func signToken(token string) string {
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(token))
	return token + "." + hex.EncodeToString(mac.Sum(nil))
}

func verifyToken(signed string) bool {
	parts := strings.SplitN(signed, ".", 2)
	if len(parts) != 2 {
		return false
	}
	expected := signToken(parts[0])
	return hmac.Equal([]byte(signed), []byte(expected)) && parts[0] == sessionToken
}

func (n *nonceStore) Issue() string {
	b := make([]byte, 32)
	rand.Read(b)
	nonce := hex.EncodeToString(b)
	n.mu.Lock()
	n.nonces[nonce] = time.Now().Add(60 * time.Second)
	n.mu.Unlock()
	return nonce
}

func (n *nonceStore) Consume(nonce string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	exp, ok := n.nonces[nonce]
	if !ok || time.Now().After(exp) {
		delete(n.nonces, nonce)
		return false
	}
	delete(n.nonces, nonce)
	return true
}

func (n *nonceStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		now := time.Now()
		n.mu.Lock()
		for k, exp := range n.nonces {
			if now.After(exp) {
				delete(n.nonces, k)
			}
		}
		n.mu.Unlock()
	}
}

func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie("kmresolv_session")
	if err != nil {
		return false
	}
	return verifyToken(cookie.Value)
}

func requireAuth(w http.ResponseWriter, r *http.Request, cfg *config.Config) bool {
	if !cfg.AuthEnabled() {
		return true
	}
	host := r.RemoteAddr
	if strings.HasPrefix(host, "127.0.0.1:") || strings.HasPrefix(host, "[::1]:") {
		return true
	}
	if isAuthenticated(r) {
		return true
	}
	http.Redirect(w, r, "/login", http.StatusFound)
	return false
}

func Start(cfg *config.Config, srv *server.Server, version string) {
	if !cfg.Dashboard.Enabled {
		return
	}

	go nonces.cleanup()

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, cfg) {
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(dashboardHTML)
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if !cfg.AuthEnabled() {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		if isAuthenticated(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(loginHTML)
			return
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc("/api/login/challenge", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		jsonOK(w, map[string]any{"nonce": nonces.Issue()})
	})

	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Username string `json:"username"`
			Response string `json:"response"`
			Nonce    string `json:"nonce"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		if !nonces.Consume(body.Nonce) {
			jsonOK(w, map[string]any{"ok": false, "error": "invalid or expired challenge"})
			return
		}

		mac := hmac.New(sha256.New, []byte(cfg.Dashboard.Auth.Password))
		mac.Write([]byte(body.Nonce))
		expected := hex.EncodeToString(mac.Sum(nil))

		userOK := hmac.Equal([]byte(body.Username), []byte(cfg.Dashboard.Auth.Username))
		passOK := hmac.Equal([]byte(body.Response), []byte(expected))

		if !userOK || !passOK {
			jsonOK(w, map[string]any{"ok": false, "error": "invalid credentials"})
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "kmresolv_session",
			Value:    signToken(sessionToken),
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   60 * 60 * 24 * 7,
		})
		jsonOK(w, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "kmresolv_session",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
		})
		http.Redirect(w, r, "/login", http.StatusFound)
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, cfg) {
			return
		}
		st := srv.Stats()

		var hitRate, avgLatency float64
		if st.TotalQueries > 0 {
			hitRate = float64(st.CacheHits) / float64(st.TotalQueries) * 100
			avgLatency = float64(st.TotalLatencyMs) / float64(st.TotalQueries)
		}

		jsonOK(w, map[string]any{
			"total_queries":  st.TotalQueries,
			"cache_hits":     st.CacheHits,
			"blocked":        st.Blocked,
			"hit_rate":       hitRate,
			"avg_latency_ms": avgLatency,
			"uptime_seconds": st.UptimeSeconds,
			"cache_size":     st.CacheSize,
			"cache_negative": st.CacheNegative,
		})
	})

	mux.HandleFunc("/api/stats/history", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, cfg) {
			return
		}
		jsonOK(w, srv.History())
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		st := srv.Stats()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintf(w, "# HELP kmresolv_queries_total Total DNS queries received\n")
		fmt.Fprintf(w, "# TYPE kmresolv_queries_total counter\n")
		fmt.Fprintf(w, "kmresolv_queries_total %d\n\n", st.TotalQueries)

		fmt.Fprintf(w, "# HELP kmresolv_cache_hits_total Queries answered from cache\n")
		fmt.Fprintf(w, "# TYPE kmresolv_cache_hits_total counter\n")
		fmt.Fprintf(w, "kmresolv_cache_hits_total %d\n\n", st.CacheHits)

		fmt.Fprintf(w, "# HELP kmresolv_blocked_total Queries blocked by filter\n")
		fmt.Fprintf(w, "# TYPE kmresolv_blocked_total counter\n")
		fmt.Fprintf(w, "kmresolv_blocked_total %d\n\n", st.Blocked)

		fmt.Fprintf(w, "# HELP kmresolv_latency_ms_total Sum of query latencies in milliseconds\n")
		fmt.Fprintf(w, "# TYPE kmresolv_latency_ms_total counter\n")
		fmt.Fprintf(w, "kmresolv_latency_ms_total %d\n\n", st.TotalLatencyMs)

		fmt.Fprintf(w, "# HELP kmresolv_cache_entries Current number of cached records\n")
		fmt.Fprintf(w, "# TYPE kmresolv_cache_entries gauge\n")
		fmt.Fprintf(w, "kmresolv_cache_entries %d\n\n", st.CacheSize)

		fmt.Fprintf(w, "# HELP kmresolv_cache_negative_entries Current number of cached NXDOMAIN responses\n")
		fmt.Fprintf(w, "# TYPE kmresolv_cache_negative_entries gauge\n")
		fmt.Fprintf(w, "kmresolv_cache_negative_entries %d\n\n", st.CacheNegative)

		fmt.Fprintf(w, "# HELP kmresolv_uptime_seconds Seconds since the server started\n")
		fmt.Fprintf(w, "# TYPE kmresolv_uptime_seconds gauge\n")
		fmt.Fprintf(w, "kmresolv_uptime_seconds %d\n", st.UptimeSeconds)
	})

	mux.HandleFunc("/api/cache/flush", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, cfg) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mode := r.URL.Query().Get("mode")
		srv.FlushCache(mode)
		jsonOK(w, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/filter/add", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, cfg) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Domain == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := srv.AddBlock(body.Domain); err != nil {
			logger.LogError("save config: %v", err)
		}
		jsonOK(w, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/filter/remove", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, cfg) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Domain == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := srv.RemoveBlock(body.Domain); err != nil {
			logger.LogError("save config: %v", err)
		}
		jsonOK(w, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/filter/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, cfg) {
			return
		}
		fs := srv.FilterStatus()
		jsonOK(w, map[string]any{
			"mode":   fs.Mode,
			"size":   fs.Size,
			"inline": fs.Inline,
		})
	})

	mux.HandleFunc("/api/filter/mode", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, cfg) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		mode := strings.ToLower(body.Mode)
		if mode != "off" && mode != "blacklist" && mode != "whitelist" {
			http.Error(w, "invalid mode", http.StatusBadRequest)
			return
		}
		if err := srv.SetFilterMode(mode); err != nil {
			logger.LogError("save config: %v", err)
			http.Error(w, "failed to save config", http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/querylog", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, cfg) {
			return
		}
		jsonOK(w, srv.RecentQueries(100))
	})

	mux.HandleFunc("/api/records", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, cfg) {
			return
		}
		type recordResp struct {
			Name  string `json:"name"`
			Type  string `json:"type"`
			Value string `json:"value"`
			TTL   uint32 `json:"ttl"`
		}
		recs := srv.ConfigRecords()
		out := make([]recordResp, 0, len(recs))
		for _, rec := range recs {
			out = append(out, recordResp{
				Name:  rec.Name,
				Type:  rec.Type,
				Value: rec.Value,
				TTL:   rec.TTL,
			})
		}
		jsonOK(w, out)
	})

	mux.HandleFunc("/api/records/remove", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, cfg) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Name string `json:"name"`
			Type string `json:"type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := srv.RemoveRecord(body.Name, body.Type); err != nil {
			logger.LogError("save config: %v", err)
			http.Error(w, "failed to save config", http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/records/add", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, cfg) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Name  string `json:"name"`
			Type  string `json:"type"`
			Value string `json:"value"`
			TTL   uint32 `json:"ttl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if body.Name == "" || body.Type == "" || body.Value == "" {
			http.Error(w, "name, type, and value are required", http.StatusBadRequest)
			return
		}
		if err := srv.AddRecord(config.RecordConfig{
			Name:  body.Name,
			Type:  body.Type,
			Value: body.Value,
			TTL:   body.TTL,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		jsonOK(w, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/update", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, cfg) {
			return
		}
		if !cfg.Updater.CheckEnabled {
			jsonOK(w, map[string]any{"available": false, "version": "", "url": ""})
			return
		}
		result, err := updater.Check(version)
		if err != nil {
			logger.LogDebug("update check failed: %v", err)
			jsonOK(w, map[string]any{"available": false, "version": "", "url": ""})
			return
		}
		jsonOK(w, map[string]any{
			"available": result.Available,
			"version":   result.Version,
			"url":       result.URL,
		})
	})

	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, cfg) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			EDNS0       *bool `json:"edns0"`
			TCPFallback *bool `json:"tcp_fallback"`
			Prefetch    *bool `json:"prefetch"`
			UpdateCheck *bool `json:"update_check"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := srv.UpdateSettings(body.EDNS0, body.TCPFallback, body.Prefetch, body.UpdateCheck); err != nil {
			logger.LogError("save config: %v", err)
			http.Error(w, "failed to save config", http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/settings/get", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, cfg) {
			return
		}
		ss := srv.GetSettings()
		jsonOK(w, map[string]any{
			"edns0":        ss.EDNS0,
			"tcp_fallback": ss.TCPFallback,
			"prefetch":     ss.Prefetch,
			"update_check": ss.UpdateCheck,
			"listen":       ss.Listen,
			"log_level":    ss.LogLevel,
			"timeout":      ss.Timeout,
			"max_depth":    ss.MaxDepth,
			"negative_ttl": ss.NegativeTTL,
		})
	})

	addr := cfg.DashboardAddr()
	if cfg.Dashboard.TLSCertFile != "" {
		logger.LogInfo("dashboard listening on https://%s", addr)
		go func() {
			if err := http.ListenAndServeTLS(addr, cfg.Dashboard.TLSCertFile, cfg.Dashboard.TLSKeyFile, mux); err != nil {
				logger.LogError("dashboard: %v", err)
			}
		}()
	} else {
		logger.LogInfo("dashboard listening on http://%s", addr)
		go func() {
			if err := http.ListenAndServe(addr, mux); err != nil {
				logger.LogError("dashboard: %v", err)
			}
		}()
	}
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
