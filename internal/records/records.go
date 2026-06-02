package records

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/kohanmathers/kmresolv/internal/config"
	"github.com/kohanmathers/kmresolv/internal/dns"
	"github.com/kohanmathers/kmresolv/internal/logger"
)

type RecordStore struct {
	records map[string][]dns.RR
}

func NewRecordStore(cfg *config.Config) *RecordStore {
	rs := &RecordStore{
		records: make(map[string][]dns.RR),
	}
	for _, r := range cfg.Records {
		rr, err := buildRR(r)
		if err != nil {
			logger.LogWarn("skipping invalid custom record %s: %v", r.Name, err)
			continue
		}
		key := strings.ToLower(r.Name)
		rs.records[key] = append(rs.records[key], rr)
		logger.LogInfo("custom record: %s %s → %s", r.Type, r.Name, r.Value)
	}
	return rs
}

func (rs *RecordStore) Lookup(name string, qtype uint16) []dns.RR {
	key := strings.ToLower(strings.TrimSuffix(name, "."))

	if rrs, ok := rs.records[key]; ok {
		return filterByType(rrs, qtype)
	}

	if idx := strings.Index(key, "."); idx != -1 {
		if rrs, ok := rs.records["*."+key[idx+1:]]; ok {
			matches := filterByType(rrs, qtype)
			for i := range matches {
				matches[i].Name = key
			}
			return matches
		}
	}

	return nil
}

func filterByType(rrs []dns.RR, qtype uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range rrs {
		if rr.Type == qtype {
			out = append(out, rr)
		}
	}
	return out
}

func buildRR(r config.RecordConfig) (dns.RR, error) {
	rr := dns.RR{
		Name:  r.Name,
		TTL:   r.TTL,
		Class: dns.ClassIN,
	}
	switch strings.ToUpper(r.Type) {
	case "A":
		ip := net.ParseIP(r.Value).To4()
		if ip == nil {
			return dns.RR{}, fmt.Errorf("invalid IPv4 address: %s", r.Value)
		}
		rr.Type = dns.TypeA
		rr.Data = ip

	case "AAAA":
		ip := net.ParseIP(r.Value).To16()
		if ip == nil {
			return dns.RR{}, fmt.Errorf("invalid IPv6 address: %s", r.Value)
		}
		rr.Type = dns.TypeAAAA
		rr.Data = ip

	case "CNAME":
		rr.Type = dns.TypeCNAME
		rr.Data = dns.PackName(r.Value)

	case "TXT":
		txt := []byte(r.Value)
		if len(txt) > 255 {
			return dns.RR{}, fmt.Errorf("TXT value too long: %d bytes", len(txt))
		}
		rr.Type = dns.TypeTXT
		rr.Data = append([]byte{byte(len(txt))}, txt...)

	case "MX":
		var pref uint16
		var target string
		if _, err := fmt.Sscanf(r.Value, "%d %s", &pref, &target); err != nil {
			return dns.RR{}, fmt.Errorf("MX value must be \"<priority> <host>\": %s", r.Value)
		}
		rr.Type = dns.TypeMX
		prefBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(prefBytes, pref)
		rr.Data = append(prefBytes, dns.PackName(target)...)

	default:
		return dns.RR{}, fmt.Errorf("unsupported type: %s", r.Type)
	}
	return rr, nil
}
