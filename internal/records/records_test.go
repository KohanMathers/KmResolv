package records

import (
	"encoding/binary"
	"testing"

	"github.com/kohanmathers/kmresolv/internal/config"
	"github.com/kohanmathers/kmresolv/internal/dns"
)

func TestBuildRR_A(t *testing.T) {
	rr, err := buildRR(config.RecordConfig{Name: "host.com", Type: "A", TTL: 60, Value: "1.2.3.4"})
	if err != nil {
		t.Fatalf("buildRR A: %v", err)
	}
	if rr.Type != dns.TypeA {
		t.Errorf("type = %d, want TypeA (%d)", rr.Type, dns.TypeA)
	}
	if rr.Class != dns.ClassIN {
		t.Errorf("class = %d, want ClassIN (%d)", rr.Class, dns.ClassIN)
	}
	if rr.TTL != 60 {
		t.Errorf("TTL = %d, want 60", rr.TTL)
	}
	if len(rr.Data) != 4 {
		t.Fatalf("expected 4 bytes for A record, got %d", len(rr.Data))
	}
	if rr.Data[0] != 1 || rr.Data[1] != 2 || rr.Data[2] != 3 || rr.Data[3] != 4 {
		t.Errorf("unexpected IP bytes: %v", rr.Data)
	}
}

func TestBuildRR_AInvalid(t *testing.T) {
	_, err := buildRR(config.RecordConfig{Name: "host.com", Type: "A", Value: "not-an-ip"})
	if err == nil {
		t.Error("expected error for invalid IPv4 address")
	}
}

func TestBuildRR_ACaseInsensitive(t *testing.T) {
	_, err := buildRR(config.RecordConfig{Name: "host.com", Type: "a", Value: "1.2.3.4"})
	if err != nil {
		t.Errorf("buildRR should accept lowercase type 'a': %v", err)
	}
}

func TestBuildRR_AAAA(t *testing.T) {
	rr, err := buildRR(config.RecordConfig{Name: "host.com", Type: "AAAA", TTL: 120, Value: "::1"})
	if err != nil {
		t.Fatalf("buildRR AAAA: %v", err)
	}
	if rr.Type != dns.TypeAAAA {
		t.Errorf("type = %d, want TypeAAAA (%d)", rr.Type, dns.TypeAAAA)
	}
	if len(rr.Data) != 16 {
		t.Fatalf("expected 16 bytes for AAAA record, got %d", len(rr.Data))
	}
	if rr.Data[15] != 1 {
		t.Errorf("last byte of ::1 should be 1, got %d", rr.Data[15])
	}
}

func TestBuildRR_AAAAInvalid(t *testing.T) {
	_, err := buildRR(config.RecordConfig{Name: "host.com", Type: "AAAA", Value: "not-ipv6"})
	if err == nil {
		t.Error("expected error for invalid IPv6 address")
	}
}

func TestBuildRR_CNAME(t *testing.T) {
	rr, err := buildRR(config.RecordConfig{Name: "alias.com", Type: "CNAME", TTL: 300, Value: "target.com"})
	if err != nil {
		t.Fatalf("buildRR CNAME: %v", err)
	}
	if rr.Type != dns.TypeCNAME {
		t.Errorf("type = %d, want TypeCNAME (%d)", rr.Type, dns.TypeCNAME)
	}
	if len(rr.Data) == 0 {
		t.Error("CNAME data should not be empty")
	}
	expected := dns.PackName("target.com")
	if string(rr.Data) != string(expected) {
		t.Errorf("CNAME data mismatch:\n  got  %v\n  want %v", rr.Data, expected)
	}
}

func TestBuildRR_TXT(t *testing.T) {
	rr, err := buildRR(config.RecordConfig{Name: "host.com", Type: "TXT", TTL: 60, Value: "hello"})
	if err != nil {
		t.Fatalf("buildRR TXT: %v", err)
	}
	if rr.Type != dns.TypeTXT {
		t.Errorf("type = %d, want TypeTXT (%d)", rr.Type, dns.TypeTXT)
	}
	if rr.Data[0] != 5 {
		t.Errorf("TXT length byte = %d, want 5", rr.Data[0])
	}
	if string(rr.Data[1:]) != "hello" {
		t.Errorf("TXT content = %q, want hello", string(rr.Data[1:]))
	}
}

func TestBuildRR_TXTTooLong(t *testing.T) {
	value := string(make([]byte, 256))
	_, err := buildRR(config.RecordConfig{Name: "host.com", Type: "TXT", Value: value})
	if err == nil {
		t.Error("expected error for TXT value exceeding 255 bytes")
	}
}

func TestBuildRR_TXTMaxLength(t *testing.T) {
	value := string(make([]byte, 255))
	_, err := buildRR(config.RecordConfig{Name: "host.com", Type: "TXT", Value: value})
	if err != nil {
		t.Errorf("255-byte TXT should be valid, got: %v", err)
	}
}

func TestBuildRR_MX(t *testing.T) {
	rr, err := buildRR(config.RecordConfig{Name: "mail.com", Type: "MX", TTL: 300, Value: "10 mail.example.com"})
	if err != nil {
		t.Fatalf("buildRR MX: %v", err)
	}
	if rr.Type != dns.TypeMX {
		t.Errorf("type = %d, want TypeMX (%d)", rr.Type, dns.TypeMX)
	}
	pref := binary.BigEndian.Uint16(rr.Data[:2])
	if pref != 10 {
		t.Errorf("MX preference = %d, want 10", pref)
	}
	if len(rr.Data) <= 2 {
		t.Error("MX data should include packed hostname after preference bytes")
	}
}

func TestBuildRR_MXInvalid(t *testing.T) {
	_, err := buildRR(config.RecordConfig{Name: "mail.com", Type: "MX", Value: "badformat"})
	if err == nil {
		t.Error("expected error for invalid MX value (no priority prefix)")
	}
}

func TestBuildRR_UnsupportedType(t *testing.T) {
	_, err := buildRR(config.RecordConfig{Name: "host.com", Type: "BOGUS", Value: "whatever"})
	if err == nil {
		t.Error("expected error for unsupported record type BOGUS")
	}
}

func TestNewRecordStore(t *testing.T) {
	cfg := &config.Config{
		Records: []config.RecordConfig{
			{Name: "host.com", Type: "A", TTL: 60, Value: "1.2.3.4"},
			{Name: "v6.com", Type: "AAAA", TTL: 60, Value: "::1"},
		},
	}
	rs := NewRecordStore(cfg)

	if rs.Lookup("host.com", dns.TypeA) == nil {
		t.Error("A record should be found")
	}
	if rs.Lookup("v6.com", dns.TypeAAAA) == nil {
		t.Error("AAAA record should be found")
	}
}

func TestLookupCaseInsensitive(t *testing.T) {
	cfg := &config.Config{
		Records: []config.RecordConfig{
			{Name: "Host.COM", Type: "A", TTL: 60, Value: "2.3.4.5"},
		},
	}
	rs := NewRecordStore(cfg)

	if rs.Lookup("host.com", dns.TypeA) == nil {
		t.Error("lookup should be case-insensitive (lowercase)")
	}
	if rs.Lookup("HOST.COM", dns.TypeA) == nil {
		t.Error("lookup should be case-insensitive (uppercase)")
	}
}

func TestLookupTrailingDot(t *testing.T) {
	cfg := &config.Config{
		Records: []config.RecordConfig{
			{Name: "host.com", Type: "A", TTL: 60, Value: "1.2.3.4"},
		},
	}
	rs := NewRecordStore(cfg)

	if rs.Lookup("host.com.", dns.TypeA) == nil {
		t.Error("trailing dot should be stripped for lookup")
	}
}

func TestLookupTypeMismatch(t *testing.T) {
	cfg := &config.Config{
		Records: []config.RecordConfig{
			{Name: "host.com", Type: "A", TTL: 60, Value: "1.2.3.4"},
		},
	}
	rs := NewRecordStore(cfg)

	if rs.Lookup("host.com", dns.TypeAAAA) != nil {
		t.Error("lookup with wrong type should return nil")
	}
}

func TestLookupMissing(t *testing.T) {
	rs := NewRecordStore(&config.Config{})

	if rs.Lookup("missing.com", dns.TypeA) != nil {
		t.Error("lookup for non-existent domain should return nil")
	}
}

func TestWildcardLookup(t *testing.T) {
	cfg := &config.Config{
		Records: []config.RecordConfig{
			{Name: "*.home", Type: "A", TTL: 60, Value: "192.168.1.1"},
		},
	}
	rs := NewRecordStore(cfg)

	rrs := rs.Lookup("pi.home", dns.TypeA)
	if len(rrs) != 1 {
		t.Fatalf("expected 1 A record for pi.home, got %d", len(rrs))
	}
	if rrs[0].Name != "pi.home" {
		t.Errorf("wildcard match should rewrite Name to queried name, got %q", rrs[0].Name)
	}
}

func TestWildcardDoesNotMatchParent(t *testing.T) {
	cfg := &config.Config{
		Records: []config.RecordConfig{
			{Name: "*.home", Type: "A", TTL: 60, Value: "192.168.1.1"},
		},
	}
	rs := NewRecordStore(cfg)

	if rs.Lookup("home", dns.TypeA) != nil {
		t.Error("wildcard should not match the parent zone itself")
	}
}

func TestWildcardDoesNotMatchDeeper(t *testing.T) {
	cfg := &config.Config{
		Records: []config.RecordConfig{
			{Name: "*.home", Type: "A", TTL: 60, Value: "192.168.1.1"},
		},
	}
	rs := NewRecordStore(cfg)

	if rs.Lookup("sub.pi.home", dns.TypeA) != nil {
		t.Error("*.home should not match two levels deep (sub.pi.home)")
	}
}

func TestWildcardExactTakesPrecedence(t *testing.T) {
	cfg := &config.Config{
		Records: []config.RecordConfig{
			{Name: "*.home", Type: "A", TTL: 60, Value: "192.168.1.1"},
			{Name: "nas.home", Type: "A", TTL: 60, Value: "192.168.1.50"},
		},
	}
	rs := NewRecordStore(cfg)

	rrs := rs.Lookup("nas.home", dns.TypeA)
	if len(rrs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(rrs))
	}
	if rrs[0].Data[3] != 50 {
		t.Errorf("exact record should take precedence over wildcard, got last octet %d", rrs[0].Data[3])
	}
}

func TestWildcardTypeMismatch(t *testing.T) {
	cfg := &config.Config{
		Records: []config.RecordConfig{
			{Name: "*.home", Type: "A", TTL: 60, Value: "192.168.1.1"},
		},
	}
	rs := NewRecordStore(cfg)

	if rs.Lookup("pi.home", dns.TypeAAAA) != nil {
		t.Error("wildcard A record should not match AAAA query")
	}
}

func TestWildcardCaseInsensitive(t *testing.T) {
	cfg := &config.Config{
		Records: []config.RecordConfig{
			{Name: "*.home", Type: "A", TTL: 60, Value: "192.168.1.1"},
		},
	}
	rs := NewRecordStore(cfg)

	if rs.Lookup("PI.HOME", dns.TypeA) == nil {
		t.Error("wildcard lookup should be case-insensitive")
	}
}

func TestNewRecordStoreSkipsInvalid(t *testing.T) {
	cfg := &config.Config{
		Records: []config.RecordConfig{
			{Name: "bad.com", Type: "A", TTL: 60, Value: "not-an-ip"},
			{Name: "good.com", Type: "A", TTL: 60, Value: "1.2.3.4"},
		},
	}
	rs := NewRecordStore(cfg)

	if rs.Lookup("bad.com", dns.TypeA) != nil {
		t.Error("invalid record should be skipped, not stored")
	}
	if rs.Lookup("good.com", dns.TypeA) == nil {
		t.Error("valid record following an invalid one should still be stored")
	}
}

func TestLookupMultipleRecordsSameHost(t *testing.T) {
	cfg := &config.Config{
		Records: []config.RecordConfig{
			{Name: "multi.com", Type: "A", TTL: 60, Value: "1.1.1.1"},
			{Name: "multi.com", Type: "A", TTL: 60, Value: "2.2.2.2"},
			{Name: "multi.com", Type: "AAAA", TTL: 60, Value: "::1"},
		},
	}
	rs := NewRecordStore(cfg)

	a := rs.Lookup("multi.com", dns.TypeA)
	if len(a) != 2 {
		t.Errorf("expected 2 A records, got %d", len(a))
	}
	aaaa := rs.Lookup("multi.com", dns.TypeAAAA)
	if len(aaaa) != 1 {
		t.Errorf("expected 1 AAAA record, got %d", len(aaaa))
	}
}
