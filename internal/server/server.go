package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kohanmathers/kmresolv/internal/cache"
	"github.com/kohanmathers/kmresolv/internal/config"
	"github.com/kohanmathers/kmresolv/internal/dns"
	"github.com/kohanmathers/kmresolv/internal/dnssec"
	"github.com/kohanmathers/kmresolv/internal/filter"
	"github.com/kohanmathers/kmresolv/internal/logger"
	"github.com/kohanmathers/kmresolv/internal/records"
)

type Server struct {
	cfg       *config.Config
	cache     *cache.Cache
	filter    *filter.Filter
	records   *records.RecordStore
	qlog      *QueryLog
	pool      *connPool
	tcpPool   *connPool
	dotPool   *connPool
	dohClient *http.Client
	limiter   *rateLimiter
	history   *statsHistory
	dnssecVal *dnssec.Validator
	rawPool   sync.Pool
	inflight  sync.Map
	sem       chan struct{}

	statTotalQueries   atomic.Uint64
	statCacheHits      atomic.Uint64
	statBlocked        atomic.Uint64
	statTotalLatencyMs atomic.Uint64

	startTime time.Time

	minecraft *MinecraftServer
}

func New(cfg *config.Config) *Server {
	s := &Server{
		cfg:     cfg,
		filter:  filter.NewFilter(cfg),
		records: records.NewRecordStore(cfg),
		qlog:    newQueryLog(500, cfg.Server.QueryLogFile),
		cache:   cache.NewCache(),
		pool:    newConnPool("udp", poolSizePerServer),
		tcpPool: newConnPool("tcp", tcpPoolSizePerServer),
		dotPool: newTLSConnPool(tcpPoolSizePerServer),
		dohClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
				TLSHandshakeTimeout: 5 * time.Second,
				ForceAttemptHTTP2:   true,
				MaxIdleConnsPerHost: 4,
			},
		},
		history:   &statsHistory{},
		startTime: time.Now(),
	}
	if cfg.Resolver.DNSSEC {
		s.dnssecVal = dnssec.NewValidator()
	}
	s.rawPool.New = func() any { return make([]byte, udpBufSize) }
	if cfg.Minecraft.Enabled {
		host := cfg.Dashboard.Listen
		if host == "0.0.0.0" {
			host = "127.0.0.1"
		}
		apiURL := fmt.Sprintf("http://%s:%d", host, cfg.Dashboard.Port)
		s.minecraft = NewMinecraftServer(&cfg.Minecraft, apiURL)
	}
	if cfg.Resolver.MaxConcurrent > 0 {
		s.sem = make(chan struct{}, cfg.Resolver.MaxConcurrent)
	}
	if cfg.Resolver.RateLimit.Enabled {
		s.limiter = newRateLimiter(cfg.Resolver.RateLimit.QPS, cfg.Resolver.RateLimit.Burst)
	}
	s.cache.SetMinTTL(uint32(cfg.Resolver.Cache.MinTTL))
	s.cache.SetPrefetchFn(func(name string, qtype uint16) (*dns.Message, error) {
		if s.cfg.Resolver.Forwarder.Enabled {
			msg, err := s.resolveViaForwarder(name, qtype)
			if err == nil || !s.cfg.Resolver.Forwarder.FallbackToIterative {
				return msg, err
			}
		}
		return s.resolveAt(name, qtype, RootServers, 0)
	})
	return s
}

func (s *Server) ReloadFilters() {
	s.filter.Reload(s.cfg)
}

func (s *Server) filterReloadLoop() {
	ticker := time.NewTicker(time.Duration(s.cfg.Filtering.ReloadIntervalHours) * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		logger.LogInfo("periodic filter reload")
		s.filter.Reload(s.cfg)
	}
}

func (s *Server) History() []HistoryBucket {
	return s.history.snapshot()
}

func (s *Server) sampleHistory() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	prev := [3]uint64{
		s.statTotalQueries.Load(),
		s.statCacheHits.Load(),
		s.statBlocked.Load(),
	}
	for range ticker.C {
		q := s.statTotalQueries.Load()
		h := s.statCacheHits.Load()
		b := s.statBlocked.Load()
		s.history.record(HistoryBucket{
			Queries: q - prev[0],
			Hits:    h - prev[1],
			Blocked: b - prev[2],
		})
		prev = [3]uint64{q, h, b}
	}
}

func (s *Server) Start() error {
	go s.sampleHistory()
	if s.cfg.Filtering.ReloadIntervalHours > 0 {
		go s.filterReloadLoop()
	}

	conn, err := net.ListenPacket("udp", s.cfg.Addr())
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer conn.Close()
	logger.LogInfo("listening on %s", s.cfg.Addr())

	numReaders := runtime.NumCPU()
	done := make(chan error, numReaders)
	for range numReaders {
		go func() {
			buf := make([]byte, udpBufSize)
			for {
				n, src, err := conn.ReadFrom(buf)
				if err != nil {
					done <- err
					return
				}
				raw := s.rawPool.Get().([]byte)
				copy(raw, buf[:n])
				go func() {
					s.handleQuery(conn, src, raw[:n])
					s.rawPool.Put(raw)
				}()
			}
		}()
	}
	return fmt.Errorf("listener exited: %w", <-done)
}

func (s *Server) handleQuery(conn net.PacketConn, src net.Addr, raw []byte) {
	start := time.Now()
	if s.limiter != nil {
		ip := sourceIP(src)
		if !s.limiter.allow(ip) {
			logger.LogDebug("rate limited query from %s", ip)
			return
		}
	}

	msg, err := dns.ParseMessage(raw)
	if err != nil {
		logger.LogError("parse error from %s: %v", src, err)
		return
	}
	if len(msg.Questions) == 0 {
		return
	}

	q := msg.Questions[0]
	logger.LogDebug("query from %s: %s type=%d", src, q.Name, q.Type)
	s.statTotalQueries.Add(1)

	tname := typeName(q.Type)

	if s.filter.Blocked(q.Name) {
		logger.LogInfo("blocked: %s from client %s", q.Name, src)
		s.statBlocked.Add(1)
		conn.WriteTo(nxdomain(msg), src)
		s.qlog.Add(QueryEntry{
			Time:    time.Now(),
			Domain:  q.Name,
			Type:    tname,
			Client:  src.String(),
			Status:  "blocked",
			Latency: time.Since(start).Milliseconds(),
		})
		return
	}

	if rrs := s.records.Lookup(q.Name, q.Type); rrs != nil {
		logger.LogDebug("custom record hit: %s", q.Name)
		resp := &dns.Message{}
		resp.ID = msg.ID
		resp.SetQR(true)
		resp.SetRA(true)
		resp.SetAA(true)
		resp.Questions = msg.Questions
		resp.Answers = rrs
		packed, err := resp.Pack()
		if err != nil {
			logger.LogError("pack error for custom record: %v", err)
			return
		}
		conn.WriteTo(packed, src)
		s.qlog.Add(QueryEntry{
			Time:    time.Now(),
			Domain:  q.Name,
			Type:    tname,
			Client:  src.String(),
			Status:  "resolved",
			Latency: time.Since(start).Milliseconds(),
		})
		return
	}

	resp, wasCached, resolveErr := s.resolve(q.Name, q.Type)

	latency := time.Since(start).Milliseconds()
	s.statTotalLatencyMs.Add(uint64(latency))

	status := "resolved"
	if resolveErr != nil {
		logger.LogWarn("resolve error for %s: %v", q.Name, resolveErr)
		packed, _ := servfail(msg).Pack()
		conn.WriteTo(packed, src)
		s.qlog.Add(QueryEntry{
			Time:    time.Now(),
			Domain:  q.Name,
			Type:    tname,
			Client:  src.String(),
			Status:  "error",
			Latency: latency,
		})
		return
	}

	if wasCached {
		status = "cached"
		s.statCacheHits.Add(1)
	}

	resp.ID = msg.ID
	resp.SetQR(true)
	resp.SetRA(true)
	resp.SetAA(false)
	resp.Questions = msg.Questions

	packed, err := resp.Pack()
	if err != nil {
		logger.LogError("pack error: %v", err)
		return
	}
	conn.WriteTo(packed, src)
	s.qlog.Add(QueryEntry{
		Time:    time.Now(),
		Domain:  q.Name,
		Type:    tname,
		Client:  src.String(),
		Status:  status,
		Latency: latency,
	})
}

type StatsSnapshot struct {
	TotalQueries   uint64
	CacheHits      uint64
	Blocked        uint64
	TotalLatencyMs uint64
	CacheSize      int
	CacheNegative  int
	UptimeSeconds  int
}

func (s *Server) Stats() StatsSnapshot {
	return StatsSnapshot{
		TotalQueries:   s.statTotalQueries.Load(),
		CacheHits:      s.statCacheHits.Load(),
		Blocked:        s.statBlocked.Load(),
		TotalLatencyMs: s.statTotalLatencyMs.Load(),
		CacheSize:      s.cache.Size(),
		CacheNegative:  s.cache.NegativeSize(),
		UptimeSeconds:  int(time.Since(s.startTime).Seconds()),
	}
}

func (s *Server) FlushCache(mode string) {
	s.cache.Flush(mode)
}

type FilterStatus struct {
	Mode   string
	Size   int
	Inline []string
}

func (s *Server) FilterStatus() FilterStatus {
	return FilterStatus{
		Mode:   s.cfg.Filtering.Mode,
		Size:   s.filter.Size(),
		Inline: s.filter.InlineDomains(),
	}
}

func (s *Server) AddBlock(domain string) error {
	s.filter.Add(domain)
	s.cfg.Filtering.Inline = append(s.cfg.Filtering.Inline, domain)
	return s.cfg.Save()
}

func (s *Server) RemoveBlock(domain string) error {
	s.filter.Remove(domain)
	updated := s.cfg.Filtering.Inline[:0]
	for _, d := range s.cfg.Filtering.Inline {
		if !strings.EqualFold(d, domain) {
			updated = append(updated, d)
		}
	}
	s.cfg.Filtering.Inline = updated
	return s.cfg.Save()
}

func (s *Server) SetFilterMode(mode string) error {
	s.cfg.Filtering.Mode = mode
	s.filter.SetMode(mode)
	return s.cfg.Save()
}

func (s *Server) RecentQueries(n int) []QueryEntry {
	return s.qlog.Recent(n)
}

func (s *Server) ConfigRecords() []config.RecordConfig {
	return s.cfg.Records
}

func (s *Server) AddRecord(r config.RecordConfig) error {
	if err := records.ValidateRecord(r); err != nil {
		return err
	}
	s.cfg.Records = append(s.cfg.Records, r)
	s.records = records.NewRecordStore(s.cfg)
	return s.cfg.Save()
}

func (s *Server) RemoveRecord(name, rtype string) error {
	updated := s.cfg.Records[:0]
	for _, rec := range s.cfg.Records {
		if !(strings.EqualFold(rec.Name, name) && strings.EqualFold(rec.Type, rtype)) {
			updated = append(updated, rec)
		}
	}
	s.cfg.Records = updated
	s.records = records.NewRecordStore(s.cfg)
	return s.cfg.Save()
}

type SettingsSnapshot struct {
	EDNS0       bool
	TCPFallback bool
	Prefetch    bool
	UpdateCheck bool
	Listen      string
	LogLevel    string
	Timeout     int
	MaxDepth    int
	NegativeTTL int
}

func (s *Server) GetSettings() SettingsSnapshot {
	return SettingsSnapshot{
		EDNS0:       s.cfg.Resolver.EDNS0,
		TCPFallback: s.cfg.Resolver.TCPFallback,
		Prefetch:    s.cfg.Resolver.Cache.Prefetch,
		UpdateCheck: s.cfg.Updater.CheckEnabled,
		Listen:      s.cfg.Addr(),
		LogLevel:    s.cfg.Server.LogLevel,
		Timeout:     s.cfg.Resolver.Timeout,
		MaxDepth:    s.cfg.Resolver.MaxDepth,
		NegativeTTL: s.cfg.Resolver.Cache.NegativeTTL,
	}
}

func (s *Server) UpdateSettings(edns0, tcpFallback, prefetch, updateCheck *bool) error {
	if edns0 != nil {
		s.cfg.Resolver.EDNS0 = *edns0
	}
	if tcpFallback != nil {
		s.cfg.Resolver.TCPFallback = *tcpFallback
	}
	if prefetch != nil {
		s.cfg.Resolver.Cache.Prefetch = *prefetch
	}
	if updateCheck != nil {
		s.cfg.Updater.CheckEnabled = *updateCheck
	}
	return s.cfg.Save()
}

func (s *Server) Cfg() *config.Config { return s.cfg }

func nxdomain(req *dns.Message) []byte {
	resp := &dns.Message{}
	resp.ID = req.ID
	resp.SetQR(true)
	resp.SetRA(true)
	resp.SetRcode(dns.RcodeNXDomain)
	resp.Questions = req.Questions
	packed, _ := resp.Pack()
	return packed
}

func servfail(req *dns.Message) *dns.Message {
	resp := &dns.Message{}
	resp.ID = req.ID
	resp.SetQR(true)
	resp.SetRA(true)
	resp.SetRcode(dns.RcodeServFail)
	resp.Questions = req.Questions
	return resp
}

func typeName(t uint16) string {
	switch t {
	case dns.TypeA:
		return "A"
	case dns.TypeNS:
		return "NS"
	case dns.TypeCNAME:
		return "CNAME"
	case dns.TypeSOA:
		return "SOA"
	case dns.TypePTR:
		return "PTR"
	case dns.TypeMX:
		return "MX"
	case dns.TypeTXT:
		return "TXT"
	case dns.TypeAAAA:
		return "AAAA"
	case dns.TypeLOC:
		return "LOC"
	case dns.TypeSRV:
		return "SRV"
	case dns.TypeNAPTR:
		return "NAPTR"
	case dns.TypeCERT:
		return "CERT"
	case dns.TypeDS:
		return "DS"
	case dns.TypeSSHFP:
		return "SSHFP"
	case dns.TypeDNSKEY:
		return "DNSKEY"
	case dns.TypeTLSA:
		return "TLSA"
	case dns.TypeSMIMEA:
		return "SMIMEA"
	case dns.TypeOPENPGPKEY:
		return "OPENPGPKEY"
	case dns.TypeSVCB:
		return "SVCB"
	case dns.TypeHTTPS:
		return "HTTPS"
	case dns.TypeURI:
		return "URI"
	case dns.TypeCAA:
		return "CAA"
	default:
		return fmt.Sprintf("%d", t)
	}
}

func (s *Server) StartMinecraft() error {
	if s.minecraft == nil {
		return fmt.Errorf("minecraft not configured")
	}
	return s.minecraft.Start()
}

func (s *Server) StopMinecraft() error {
	if s.minecraft == nil {
		return nil
	}
	return s.minecraft.Stop()
}

func (s *Server) MinecraftRunning() bool {
	if s.minecraft == nil {
		return false
	}
	return s.minecraft.Running()
}
