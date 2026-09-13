package dns

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestParseRealQuery(t *testing.T) {
	raw, _ := hex.DecodeString(
		"b96201000001000000000000" +
			"06676f6f676c65" +
			"03636f6d00" +
			"0001" +
			"0001",
	)

	m, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(m.Questions) != 1 {
		t.Fatalf("expected 1 question, got %d", len(m.Questions))
	}
	q := m.Questions[0]
	if q.Name != "google.com" {
		t.Errorf("expected google.com, got %q", q.Name)
	}
	if q.Type != TypeA {
		t.Errorf("expected type A, got %d", q.Type)
	}
	t.Logf("parsed: %s type=%d class=%d", q.Name, q.Type, q.Class)
}

func TestPackRoundtrip(t *testing.T) {
	m := &Message{}
	m.ID = 0x1234
	m.SetRD(true)
	m.Questions = []Question{{Name: "example.com", Type: TypeA, Class: ClassIN}}

	packed, err := m.Pack()
	if err != nil {
		t.Fatalf("pack error: %v", err)
	}
	m2, err := ParseMessage(packed)
	if err != nil {
		t.Fatalf("reparse error: %v", err)
	}
	if m2.Questions[0].Name != "example.com" {
		t.Errorf("roundtrip name mismatch: got %q", m2.Questions[0].Name)
	}
	if !m2.RD() {
		t.Error("RD bit lost in roundtrip")
	}
	t.Logf("roundtrip OK, %d bytes", len(packed))
}

func TestPackDeepCNAMEChain(t *testing.T) {
	m := &Message{}
	m.ID = 0x1111
	m.SetQR(true)
	m.SetRA(true)
	m.Questions = []Question{{Name: "apis.roblox.com", Type: TypeA, Class: ClassIN}}
	m.Answers = []RR{
		{Name: "apis.roblox.com", Type: TypeCNAME, Class: ClassIN, TTL: 60, Data: PackName("titanium.roblox.com")},
		{Name: "titanium.roblox.com", Type: TypeCNAME, Class: ClassIN, TTL: 60, Data: PackName("edge-term4.roblox.com")},
		{Name: "edge-term4.roblox.com", Type: TypeCNAME, Class: ClassIN, TTL: 60, Data: PackName("edge-term4-lhr4.roblox.com")},
		{Name: "edge-term4-lhr4.roblox.com", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{128, 116, 31, 3}},
	}

	packed, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	got, err := ParseMessage(packed)
	if err != nil {
		t.Fatalf("ParseMessage (dig-style label walk): %v\nhex: %s", err, hex.EncodeToString(packed))
	}
	if len(got.Answers) != 4 {
		t.Fatalf("answers = %d, want 4", len(got.Answers))
	}

	wantNames := []string{
		"apis.roblox.com",
		"titanium.roblox.com",
		"edge-term4.roblox.com",
		"edge-term4-lhr4.roblox.com",
	}
	wantTypes := []uint16{TypeCNAME, TypeCNAME, TypeCNAME, TypeA}
	for i, rr := range got.Answers {
		if rr.Name != wantNames[i] {
			t.Errorf("answer[%d].Name = %q, want %q", i, rr.Name, wantNames[i])
		}
		if rr.Type != wantTypes[i] {
			t.Errorf("answer[%d].Type = %d, want %d", i, rr.Type, wantTypes[i])
		}
	}

	target, _, err := ParseName(got.Raw, got.Answers[2].Offset)
	if err != nil {
		t.Fatalf("third CNAME target: %v", err)
	}
	if target != "edge-term4-lhr4.roblox.com" {
		t.Errorf("third CNAME target = %q, want edge-term4-lhr4.roblox.com", target)
	}

	ip, err := ParseA(got.Answers[3].Data)
	if err != nil {
		t.Fatalf("A rdata: %v", err)
	}
	if ip != "128.116.31.3" {
		t.Errorf("A = %s, want 128.116.31.3", ip)
	}

	if bytes.Contains(packed, []byte{0xC0, 0x17}) {
		t.Error("packed message contains pointer to 0x17 (would be 'x' in apis.roblox.com)")
	}

	full := PackName("edge-term4-lhr4.roblox.com")
	if bytes.Contains(packed, full) {
		t.Error("A-record owner was written uncompressed instead of a pointer to the CNAME target just encoded")
	}

	label := append([]byte{0x0f}, []byte("edge-term4-lhr4")...)
	idx := bytes.Index(packed, label)
	if idx < 0 {
		t.Fatal("missing edge-term4-lhr4 label in CNAME rdata")
	}
	if idx+len(label)+1 >= len(packed) || packed[idx+len(label)]&0xC0 != 0xC0 {
		t.Errorf("CNAME rdata for edge-term4-lhr4 should end with a compression pointer, got %x", packed[idx+len(label):min(idx+len(label)+4, len(packed))])
	}
}

func TestPackCNAMEChainFromParsedInner(t *testing.T) {
	inner := &Message{}
	inner.SetQR(true)
	inner.Questions = []Question{{Name: "edge-term4.roblox.com", Type: TypeA, Class: ClassIN}}
	inner.Answers = []RR{
		{Name: "edge-term4.roblox.com", Type: TypeCNAME, Class: ClassIN, TTL: 60, Data: PackName("edge-term4-lhr4.roblox.com")},
		{Name: "edge-term4-lhr4.roblox.com", Type: TypeA, Class: ClassIN, TTL: 60, Data: []byte{128, 116, 31, 3}},
	}
	innerWire, err := inner.Pack()
	if err != nil {
		t.Fatalf("pack inner: %v", err)
	}
	parsed, err := ParseMessage(innerWire)
	if err != nil {
		t.Fatalf("parse inner: %v", err)
	}

	out := &Message{}
	out.ID = 0x2222
	out.SetQR(true)
	out.SetRA(true)
	out.Questions = []Question{{Name: "apis.roblox.com", Type: TypeA, Class: ClassIN}}
	out.Answers = []RR{
		{Name: "apis.roblox.com", Type: TypeCNAME, Class: ClassIN, TTL: 60, Data: PackName("titanium.roblox.com")},
		{Name: "titanium.roblox.com", Type: TypeCNAME, Class: ClassIN, TTL: 60, Data: PackName("edge-term4.roblox.com")},
		parsed.Answers[0],
		parsed.Answers[1],
	}
	out.Raw = parsed.Raw

	packed, err := out.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	got, err := ParseMessage(packed)
	if err != nil {
		t.Fatalf("reparse: %v\nhex: %s", err, hex.EncodeToString(packed))
	}
	if got.Answers[2].Name != "edge-term4.roblox.com" {
		t.Errorf("inner CNAME owner = %q", got.Answers[2].Name)
	}
	target, _, err := ParseName(got.Raw, got.Answers[2].Offset)
	if err != nil {
		t.Fatalf("inner CNAME target: %v", err)
	}
	if target != "edge-term4-lhr4.roblox.com" {
		t.Errorf("inner CNAME target = %q", target)
	}
	if !bytes.Equal(got.Answers[3].Data, []byte{128, 116, 31, 3}) {
		t.Errorf("A rdata = %v", got.Answers[3].Data)
	}
}
