package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kohanmathers/kmresolv/internal/dns"
	"github.com/kohanmathers/kmresolv/internal/logger"
)

type inflightCall struct {
	done chan struct{}
	msg  *dns.Message
	err  error
}

func inflightKey(name string, qtype uint16) string {
	return name + ":" + strconv.FormatUint(uint64(qtype), 10)
}

// Last updated: 7th May 2026 14:14 UTC
var RootServers = []string{
	"198.41.0.4",
	"170.247.170.2",
	"192.33.4.12",
	"199.7.91.13",
	"192.203.230.10",
	"192.5.5.241",
	"192.112.36.4",
	"198.97.190.53",
	"192.36.148.17",
	"192.58.128.30",
	"193.0.14.129",
	"199.7.83.42",
	"202.12.27.33",
}

const udpBufSize = 4096

func (s *Server) resolve(name string, qtype uint16) (*dns.Message, bool, error) {
	if s.cache.IsNegative(name, qtype) {
		logger.LogDebug("negative cache hit: %s", name)
		return nil, false, fmt.Errorf("NXDOMAIN: %s does not exist", name)
	}
	if msg := s.cache.Get(name, qtype, s.cfg); msg != nil {
		logger.LogDebug("cache hit: %s", name)
		return msg, true, nil
	}

	key := inflightKey(name, qtype)
	call := &inflightCall{done: make(chan struct{})}
	if actual, loaded := s.inflight.LoadOrStore(key, call); loaded {
		existing := actual.(*inflightCall)
		<-existing.done
		return existing.msg, false, existing.err
	}

	defer func() {
		s.inflight.Delete(key)
		close(call.done)
	}()

	if s.sem != nil {
		s.sem <- struct{}{}
		defer func() { <-s.sem }()
	}

	var msg *dns.Message
	var err error

	if s.cfg.Resolver.Forwarder.Enabled {
		msg, err = s.resolveViaForwarder(name, qtype)
		if err != nil && s.cfg.Resolver.Forwarder.FallbackToIterative {
			logger.LogDebug("forwarder failed, falling back to iterative: %s (%v)", name, err)
			msg, err = s.resolveAt(name, qtype, RootServers, 0)
		}
	} else {
		msg, err = s.resolveAt(name, qtype, RootServers, 0)
	}

	if err != nil {
		if strings.Contains(err.Error(), "NXDOMAIN") {
			s.cache.SetNegative(name, qtype, s.cfg.Resolver.Cache.NegativeTTL)
		}
		call.err = err
		return nil, false, err
	}
	s.cache.Set(name, qtype, msg)
	call.msg = msg
	return msg, false, nil
}

func forwarderAddr(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return server + ":53"
}

func dotAddr(server string) string {
	addr := strings.TrimPrefix(server, "tls://")
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return addr + ":853"
	}
	return addr
}

func (s *Server) resolveViaForwarder(name string, qtype uint16) (*dns.Message, error) {
	timeout := time.Duration(s.cfg.Resolver.Timeout) * time.Second
	for _, upstream := range s.cfg.Resolver.Forwarder.Servers {
		var msg *dns.Message
		var err error
		switch {
		case strings.HasPrefix(upstream, "https://"):
			msg, err = s.queryDoH(upstream, name, qtype, timeout)
		case strings.HasPrefix(upstream, "tls://"):
			msg, err = s.queryDoT(dotAddr(upstream), name, qtype)
		default:
			msg, err = s.queryForwarder(forwarderAddr(upstream), name, qtype, timeout)
		}
		if err != nil {
			logger.LogDebug("forwarder %s failed for %s: %v", upstream, name, err)
			if strings.Contains(err.Error(), "NXDOMAIN") {
				return nil, err
			}
			continue
		}
		return msg, nil
	}
	return nil, fmt.Errorf("all forwarders failed for %s", name)
}

func (s *Server) queryForwarder(server, name string, qtype uint16, timeout time.Duration) (*dns.Message, error) {
	conn, err := s.pool.get(server, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	failed := true
	defer func() { s.pool.put(server, conn, failed) }()

	req := s.buildQuery(name, qtype)
	req.SetRD(true)
	req.ID = conn.nextID
	conn.nextID++
	packed, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}
	if _, err := conn.Write(packed); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	buf := s.rawPool.Get().([]byte)
	n, err := conn.Read(buf)
	if err != nil {
		s.rawPool.Put(buf)
		return nil, fmt.Errorf("read: %w", err)
	}
	resp, err := dns.ParseMessage(buf[:n])
	s.rawPool.Put(buf)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if resp.ID != req.ID {
		return nil, fmt.Errorf("ID mismatch: got %d want %d", resp.ID, req.ID)
	}
	if resp.Rcode() == dns.RcodeNXDomain {
		failed = false
		return nil, fmt.Errorf("NXDOMAIN: %s does not exist", name)
	}
	if resp.Rcode() != dns.RcodeNoError {
		failed = false
		return nil, fmt.Errorf("rcode %d from forwarder %s", resp.Rcode(), server)
	}
	if resp.Flags&0x0200 != 0 && s.cfg.Resolver.TCPFallback {
		failed = false
		return s.queryTCP(server, name, qtype)
	}
	failed = false
	return resp, nil
}

func (s *Server) resolveAt(name string, qtype uint16, servers []string, depth int) (*dns.Message, error) {
	if depth > s.cfg.Resolver.MaxDepth {
		return nil, fmt.Errorf("max referral depth exceeded resolving %s", name)
	}

	shuffled := make([]string, len(servers))
	copy(shuffled, servers)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	var lastErr error
	for _, sv := range shuffled {
		server := sv + ":53"
		resp, err := s.query(server, name, qtype)
		if err != nil {
			logger.LogDebug("server %s failed for %s: %v — trying next", server, name, err)
			lastErr = err
			continue
		}

		if len(resp.Answers) > 0 {
			if qtype != dns.TypeCNAME {
				for _, rr := range resp.Answers {
					if rr.Type == dns.TypeCNAME {
						target, err := parseCNAME(resp, rr)
						if err != nil {
							return nil, fmt.Errorf("cname parse: %w", err)
						}
						logger.LogDebug("following CNAME %s → %s", name, target)
						if s.cache.IsNegative(target, qtype) {
							return nil, fmt.Errorf("NXDOMAIN: %s does not exist", target)
						}
						if cached := s.cache.Get(target, qtype, s.cfg); cached != nil {
							logger.LogDebug("CNAME target cache hit: %s", target)
							return cached, nil
						}
						return s.resolveAt(target, qtype, RootServers, depth+1)
					}
				}
			}
			return resp, nil
		}

		nsNames := extractNS(resp)
		if len(nsNames) == 0 {
			return resp, nil
		}

		logger.LogDebug("referral from %s → %v (depth %d)", server, nsNames, depth)

		glue := extractGlue(resp, nsNames)
		if len(glue) > 0 {
			return s.resolveAt(name, qtype, glue, depth+1)
		}

		nsIPs, err := s.resolveNSParallel(nsNames, depth)
		if err != nil {
			lastErr = err
			continue
		}
		return s.resolveAt(name, qtype, nsIPs, depth+1)
	}

	return nil, fmt.Errorf("all servers failed for %s: %w", name, lastErr)
}

func (s *Server) buildQuery(name string, qtype uint16) *dns.Message {
	req := &dns.Message{}
	req.ID = uint16(rand.Intn(65535))
	req.SetRD(false)
	req.Questions = []dns.Question{{Name: name, Type: qtype, Class: dns.ClassIN}}

	if s.cfg.Resolver.EDNS0 {
		req.Additional = append(req.Additional, dns.RR{
			Name:  "",
			Type:  41,
			Class: 4096,
			TTL:   0,
			Data:  []byte{},
		})
	}
	return req
}

func (s *Server) query(server, name string, qtype uint16) (*dns.Message, error) {
	fullTimeout := time.Duration(s.cfg.Resolver.Timeout) * time.Second
	timeout := fullTimeout
	if ms := s.cfg.Resolver.AttemptTimeoutMs; ms > 0 {
		timeout = min(time.Duration(ms)*time.Millisecond, fullTimeout)
	}
	conn, err := s.pool.get(server, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	failed := true
	defer func() { s.pool.put(server, conn, failed) }()

	req := s.buildQuery(name, qtype)
	req.ID = conn.nextID
	conn.nextID++
	packed, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}
	if _, err := conn.Write(packed); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	buf := s.rawPool.Get().([]byte)
	n, err := conn.Read(buf)
	if err != nil {
		s.rawPool.Put(buf)
		return nil, fmt.Errorf("read: %w", err)
	}
	resp, err := dns.ParseMessage(buf[:n])
	s.rawPool.Put(buf)
	if err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if resp.ID != req.ID {
		return nil, fmt.Errorf("response ID mismatch: got %d want %d", resp.ID, req.ID)
	}
	if resp.Rcode() == dns.RcodeNXDomain {
		failed = false
		return nil, fmt.Errorf("NXDOMAIN: %s does not exist", name)
	}
	if resp.Rcode() != dns.RcodeNoError {
		failed = false
		return nil, fmt.Errorf("rcode %d from %s", resp.Rcode(), server)
	}
	if resp.Flags&0x0200 != 0 && s.cfg.Resolver.TCPFallback {
		logger.LogDebug("response truncated, retrying over TCP: %s", server)
		failed = false
		return s.queryTCP(server, name, qtype)
	}

	failed = false
	return resp, nil
}

func (s *Server) queryTCP(server, name string, qtype uint16) (*dns.Message, error) {
	return s.queryTCPPool(s.tcpPool, server, name, qtype)
}

func (s *Server) queryDoT(server, name string, qtype uint16) (*dns.Message, error) {
	return s.queryTCPPool(s.dotPool, server, name, qtype)
}

func (s *Server) queryTCPPool(pool *connPool, server, name string, qtype uint16) (*dns.Message, error) {
	timeout := time.Duration(s.cfg.Resolver.Timeout) * time.Second
	conn, err := pool.get(server, timeout)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}
	failed := true
	defer func() { pool.put(server, conn, failed) }()

	req := s.buildQuery(name, qtype)
	req.ID = conn.nextID
	conn.nextID++
	packed, err := req.Pack()
	if err != nil {
		return nil, err
	}

	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(packed)))
	if _, err := conn.Write(append(length[:], packed...)); err != nil {
		return nil, fmt.Errorf("tcp write: %w", err)
	}

	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, fmt.Errorf("tcp read length: %w", err)
	}
	msgLen := int(binary.BigEndian.Uint16(length[:]))
	buf := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("tcp read body: %w", err)
	}

	resp, err := dns.ParseMessage(buf)
	if err != nil {
		return nil, fmt.Errorf("tcp parse: %w", err)
	}
	if resp.ID != req.ID {
		return nil, fmt.Errorf("tcp ID mismatch: got %d want %d", resp.ID, req.ID)
	}
	if resp.Rcode() == dns.RcodeNXDomain {
		failed = false
		return nil, fmt.Errorf("NXDOMAIN: %s does not exist", name)
	}
	if resp.Rcode() != dns.RcodeNoError {
		failed = false
		return nil, fmt.Errorf("rcode %d from %s (tcp)", resp.Rcode(), server)
	}
	failed = false
	return resp, nil
}

func (s *Server) queryDoH(dohURL, name string, qtype uint16, timeout time.Duration) (*dns.Message, error) {
	req := s.buildQuery(name, qtype)
	req.SetRD(true)
	req.ID = uint16(rand.Uint32())

	packed, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("doh pack: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL, bytes.NewReader(packed))
	if err != nil {
		return nil, fmt.Errorf("doh request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	httpResp, err := s.dohClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("doh http: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh http status %d from %s", httpResp.StatusCode, dohURL)
	}

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 65535))
	if err != nil {
		return nil, fmt.Errorf("doh read: %w", err)
	}

	resp, err := dns.ParseMessage(body)
	if err != nil {
		return nil, fmt.Errorf("doh parse: %w", err)
	}
	if resp.Rcode() == dns.RcodeNXDomain {
		return nil, fmt.Errorf("NXDOMAIN: %s does not exist", name)
	}
	if resp.Rcode() != dns.RcodeNoError {
		return nil, fmt.Errorf("rcode %d from doh %s", resp.Rcode(), dohURL)
	}
	return resp, nil
}

func extractNS(m *dns.Message) []string {
	var names []string
	for _, rr := range m.Authority {
		if rr.Type == dns.TypeNS {
			name, _, err := dns.ParseName(m.Raw, rr.Offset)
			if err == nil {
				names = append(names, name)
			}
		}
	}
	return names
}

func extractGlue(m *dns.Message, nsNames []string) []string {
	nsSet := make(map[string]bool)
	for _, n := range nsNames {
		nsSet[strings.ToLower(n)] = true
	}
	var ips []string
	for _, rr := range m.Additional {
		if !nsSet[strings.ToLower(rr.Name)] {
			continue
		}
		switch rr.Type {
		case dns.TypeA:
			if ip, err := dns.ParseA(rr.Data); err == nil {
				ips = append(ips, ip)
			}
		case dns.TypeAAAA:
			if len(rr.Data) == 16 {
				ips = append(ips, "["+net.IP(rr.Data).String()+"]")
			}
		}
	}
	return ips
}

func parseCNAME(m *dns.Message, rr dns.RR) (string, error) {
	name, _, err := dns.ParseName(m.Raw, rr.Offset)
	return name, err
}

func (s *Server) resolveNSAddr(ns string, qtype uint16, depth int) (*dns.Message, error) {
	if s.cache.IsNegative(ns, qtype) {
		return nil, fmt.Errorf("NXDOMAIN: %s does not exist", ns)
	}
	if cached := s.cache.Get(ns, qtype, s.cfg); cached != nil {
		logger.LogDebug("NS addr cache hit: %s", ns)
		return cached, nil
	}
	return s.resolveAt(ns, qtype, RootServers, depth+1)
}

func (s *Server) resolveNSParallel(nsNames []string, depth int) ([]string, error) {
	type result struct {
		ips []string
		err error
	}

	results := make(chan result, len(nsNames))

	for _, ns := range nsNames {
		ns := ns
		go func() {
			aCh := make(chan []string, 1)
			aaaaCh := make(chan []string, 1)

			go func() {
				var ips []string
				if r, err := s.resolveNSAddr(ns, dns.TypeA, depth); err != nil {
					logger.LogDebug("parallel NS resolve A failed for %s: %v", ns, err)
				} else {
					for _, rr := range r.Answers {
						if rr.Type == dns.TypeA {
							if ip, err := dns.ParseA(rr.Data); err == nil {
								ips = append(ips, ip)
							}
						}
					}
				}
				aCh <- ips
			}()

			go func() {
				var ips []string
				if r, err := s.resolveNSAddr(ns, dns.TypeAAAA, depth); err != nil {
					logger.LogDebug("parallel NS resolve AAAA failed for %s: %v", ns, err)
				} else {
					for _, rr := range r.Answers {
						if rr.Type == dns.TypeAAAA && len(rr.Data) == 16 {
							ips = append(ips, "["+net.IP(rr.Data).String()+"]")
						}
					}
				}
				aaaaCh <- ips
			}()

			var ips []string
			select {
			case ips = <-aCh:
				if len(ips) == 0 {
					ips = <-aaaaCh
				}
			case ips = <-aaaaCh:
				if len(ips) == 0 {
					ips = <-aCh
				}
			}

			if len(ips) == 0 {
				results <- result{err: fmt.Errorf("no IPs found for NS %s", ns)}
				return
			}
			results <- result{ips: ips}
		}()
	}

	var allIPs []string
	var lastErr error
	for range nsNames {
		r := <-results
		if r.err != nil {
			lastErr = r.err
			continue
		}
		allIPs = append(allIPs, r.ips...)
	}

	if len(allIPs) == 0 {
		if lastErr != nil {
			return nil, fmt.Errorf("all NS resolutions failed: %w", lastErr)
		}
		return nil, fmt.Errorf("no IPs found for any NS")
	}

	return allIPs, nil
}
