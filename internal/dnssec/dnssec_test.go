package dnssec

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/kohanmathers/kmresolv/internal/dns"
)

func TestWireName(t *testing.T) {
	tests := []struct {
		in   string
		want []byte
	}{
		{"", []byte{0}},
		{".", []byte{0}},
		{"com", []byte{3, 'c', 'o', 'm', 0}},
		{"com.", []byte{3, 'c', 'o', 'm', 0}},
		{"COM", []byte{3, 'c', 'o', 'm', 0}},
		{"example.com", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{"Example.COM.", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
	}
	for _, tc := range tests {
		got := WireName(tc.in)
		if string(got) != string(tc.want) {
			t.Errorf("WireName(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestLabelCount(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"", 0},
		{".", 0},
		{"com", 1},
		{"example.com", 2},
		{"www.example.com", 3},
		{"www.example.com.", 3},
	}
	for _, tc := range tests {
		if got := labelCount(tc.in); got != tc.want {
			t.Errorf("labelCount(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestIsRootZone(t *testing.T) {
	if !isRootZone(".") || !isRootZone("") {
		t.Error("expected . and empty string to be root zone")
	}
	if isRootZone("com") || isRootZone("example.com") {
		t.Error("non-root names should not match")
	}
}

func TestFQDN(t *testing.T) {
	if fqdn("example.com") != "example.com." {
		t.Error("missing trailing dot")
	}
	if fqdn("example.com.") != "example.com." {
		t.Error("double trailing dot")
	}
}

func TestParseUncompressedName(t *testing.T) {
	wire := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	name, n, err := parseUncompressedName(wire)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "example.com" {
		t.Errorf("got %q, want example.com", name)
	}
	if n != len(wire) {
		t.Errorf("consumed %d bytes, want %d", n, len(wire))
	}

	name, n, err = parseUncompressedName([]byte{0})
	if err != nil || name != "." || n != 1 {
		t.Errorf("root: got name=%q n=%d err=%v", name, n, err)
	}

	_, _, err = parseUncompressedName([]byte{7, 'a'})
	if err == nil {
		t.Error("expected error on truncated name")
	}

	_, _, err = parseUncompressedName([]byte{0xC0, 0x0C})
	if err == nil {
		t.Error("expected error on compression pointer")
	}
}

func TestParseDNSKEY(t *testing.T) {
	data := make([]byte, 8)
	binary.BigEndian.PutUint16(data[0:], 257)
	data[2] = 3
	data[3] = AlgRSASHA256
	data[4], data[5], data[6], data[7] = 0xAA, 0xBB, 0xCC, 0xDD

	rr := dns.RR{Type: dns.TypeDNSKEY, Data: data}
	key, err := ParseDNSKEY(rr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key.Flags != 257 || key.Protocol != 3 || key.Algorithm != AlgRSASHA256 {
		t.Errorf("unexpected fields: %+v", key)
	}
	if len(key.PublicKey) != 4 {
		t.Errorf("unexpected public key length %d", len(key.PublicKey))
	}

	if _, err := ParseDNSKEY(dns.RR{Type: dns.TypeA, Data: data}); err == nil {
		t.Error("expected error for wrong type")
	}
	if _, err := ParseDNSKEY(dns.RR{Type: dns.TypeDNSKEY, Data: data[:2]}); err == nil {
		t.Error("expected error for short rdata")
	}
}

func TestParseDS(t *testing.T) {
	data := make([]byte, 8)
	binary.BigEndian.PutUint16(data[0:], 1234)
	data[2] = AlgRSASHA256
	data[3] = DigestTypeSHA256
	copy(data[4:], []byte{0x01, 0x02, 0x03, 0x04})

	rr := dns.RR{Type: dns.TypeDS, Data: data}
	ds, err := ParseDS(rr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ds.KeyTag != 1234 || ds.Algorithm != AlgRSASHA256 || ds.DigestType != DigestTypeSHA256 {
		t.Errorf("unexpected fields: %+v", ds)
	}

	if _, err := ParseDS(dns.RR{Type: dns.TypeA, Data: data}); err == nil {
		t.Error("expected error for wrong type")
	}
	if _, err := ParseDS(dns.RR{Type: dns.TypeDS, Data: data[:2]}); err == nil {
		t.Error("expected error for short rdata")
	}
}

func TestParseRRSIG(t *testing.T) {
	signerWire := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	sig := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	data := make([]byte, 18+len(signerWire)+len(sig))
	binary.BigEndian.PutUint16(data[0:], dns.TypeA)
	data[2] = AlgRSASHA256
	data[3] = 2
	binary.BigEndian.PutUint32(data[4:], 300)
	binary.BigEndian.PutUint32(data[8:], 1800000000)
	binary.BigEndian.PutUint32(data[12:], 1700000000)
	binary.BigEndian.PutUint16(data[16:], 5678)
	copy(data[18:], signerWire)
	copy(data[18+len(signerWire):], sig)

	rr := dns.RR{Type: dns.TypeRRSIG, Data: data}
	r, err := ParseRRSIG(rr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.TypeCovered != dns.TypeA || r.Algorithm != AlgRSASHA256 || r.Labels != 2 {
		t.Errorf("unexpected header fields: %+v", r)
	}
	if r.OrigTTL != 300 || r.Expiration != 1800000000 || r.Inception != 1700000000 {
		t.Errorf("unexpected time fields: %+v", r)
	}
	if r.KeyTag != 5678 {
		t.Errorf("keytag %d, want 5678", r.KeyTag)
	}
	if r.SignerName != "example.com" {
		t.Errorf("signer %q, want example.com", r.SignerName)
	}

	if _, err := ParseRRSIG(dns.RR{Type: dns.TypeA, Data: data}); err == nil {
		t.Error("expected error for wrong type")
	}
	if _, err := ParseRRSIG(dns.RR{Type: dns.TypeRRSIG, Data: data[:10]}); err == nil {
		t.Error("expected error for short rdata")
	}
}

func TestKeyTag_RootAnchors(t *testing.T) {
	anchors := rootTrustAnchors()
	tags := make(map[uint16]bool)
	for _, a := range anchors {
		tags[KeyTag(a)] = true
	}
	if !tags[20326] {
		t.Error("KSK-2017 keytag 20326 not found")
	}
	if !tags[38696] {
		t.Error("KSK-2024 keytag 38696 not found")
	}
}

func TestVerifyDS_SHA256(t *testing.T) {
	key := DNSKEY{
		Flags:     257,
		Protocol:  3,
		Algorithm: AlgRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}
	zone := "example.com"
	input := append(WireName(zone), dnskeyRdata(key)...)
	h := sha256.Sum256(input)
	ds := DS{
		KeyTag:     KeyTag(key),
		Algorithm:  AlgRSASHA256,
		DigestType: DigestTypeSHA256,
		Digest:     h[:],
	}
	if err := VerifyDS(zone, key, ds); err != nil {
		t.Fatalf("VerifyDS: %v", err)
	}
}

func TestVerifyDS_DigestMismatch(t *testing.T) {
	key := DNSKEY{Flags: 257, Protocol: 3, Algorithm: AlgRSASHA256, PublicKey: []byte{1, 2, 3, 4}}
	ds := DS{
		KeyTag:     KeyTag(key),
		Algorithm:  AlgRSASHA256,
		DigestType: DigestTypeSHA256,
		Digest:     make([]byte, 32),
	}
	if err := VerifyDS("example.com", key, ds); err == nil {
		t.Fatal("expected digest mismatch error")
	}
}

func TestVerifyDS_KeyTagMismatch(t *testing.T) {
	key := DNSKEY{Flags: 257, Protocol: 3, Algorithm: AlgRSASHA256, PublicKey: []byte{1, 2, 3, 4}}
	input := append(WireName("example.com"), dnskeyRdata(key)...)
	h := sha256.Sum256(input)
	ds := DS{
		KeyTag:     KeyTag(key) + 1,
		Algorithm:  AlgRSASHA256,
		DigestType: DigestTypeSHA256,
		Digest:     h[:],
	}
	if err := VerifyDS("example.com", key, ds); err == nil {
		t.Fatal("expected key tag mismatch error")
	}
}

func TestVerifyDS_UnsupportedDigestType(t *testing.T) {
	key := DNSKEY{Flags: 257, Protocol: 3, Algorithm: AlgRSASHA256, PublicKey: []byte{1, 2, 3}}
	ds := DS{KeyTag: KeyTag(key), Algorithm: AlgRSASHA256, DigestType: 99, Digest: []byte{0}}
	if err := VerifyDS("example.com", key, ds); err == nil {
		t.Fatal("expected error for unsupported digest type")
	}
}

func makeRRset() []dns.RR {
	return []dns.RR{{
		Name:  "example.com",
		Type:  dns.TypeA,
		Class: dns.ClassIN,
		TTL:   300,
		Data:  []byte{93, 184, 216, 34},
	}}
}

func makeRRSIGBase(alg uint8, keyTag uint16) RRSIG {
	now := uint32(time.Now().Unix())
	return RRSIG{
		TypeCovered: dns.TypeA,
		Algorithm:   alg,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  now + 3600,
		Inception:   now - 3600,
		KeyTag:      keyTag,
		SignerName:  "example.com",
	}
}

func TestVerifyRRSIG_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := DNSKEY{Flags: 256, Protocol: 3, Algorithm: AlgED25519, PublicKey: []byte(pub)}
	rrset := makeRRset()
	sig := makeRRSIGBase(AlgED25519, KeyTag(key))
	signed := buildSignedData(sig, rrset, nil)
	sig.Signature = ed25519.Sign(priv, signed)

	keys := map[uint16]DNSKEY{KeyTag(key): key}
	if err := VerifyRRSIG(keys, rrset, sig, nil); err != nil {
		t.Fatalf("valid Ed25519 RRSIG rejected: %v", err)
	}
}

func TestVerifyRRSIG_Ed25519_BadSig(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := DNSKEY{Flags: 256, Protocol: 3, Algorithm: AlgED25519, PublicKey: []byte(pub)}
	sig := makeRRSIGBase(AlgED25519, KeyTag(key))
	sig.Signature = make([]byte, ed25519.SignatureSize)

	keys := map[uint16]DNSKEY{KeyTag(key): key}
	if err := VerifyRRSIG(keys, makeRRset(), sig, nil); err == nil {
		t.Fatal("expected error for bad signature")
	}
}

func TestVerifyRRSIG_ECDSAP256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes := make([]byte, 64)
	priv.X.FillBytes(pubBytes[:32])
	priv.Y.FillBytes(pubBytes[32:])
	key := DNSKEY{Flags: 256, Protocol: 3, Algorithm: AlgECDSAP256SHA256, PublicKey: pubBytes}

	rrset := makeRRset()
	sig := makeRRSIGBase(AlgECDSAP256SHA256, KeyTag(key))
	signed := buildSignedData(sig, rrset, nil)
	h := sha256.Sum256(signed)
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sigBytes := make([]byte, 64)
	r.FillBytes(sigBytes[:32])
	s.FillBytes(sigBytes[32:])
	sig.Signature = sigBytes

	keys := map[uint16]DNSKEY{KeyTag(key): key}
	if err := VerifyRRSIG(keys, rrset, sig, nil); err != nil {
		t.Fatalf("valid ECDSA P-256 RRSIG rejected: %v", err)
	}
}

func TestVerifyRRSIG_ECDSAP256_BadSig(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes := make([]byte, 64)
	priv.X.FillBytes(pubBytes[:32])
	priv.Y.FillBytes(pubBytes[32:])
	key := DNSKEY{Flags: 256, Protocol: 3, Algorithm: AlgECDSAP256SHA256, PublicKey: pubBytes}
	sig := makeRRSIGBase(AlgECDSAP256SHA256, KeyTag(key))

	r := new(big.Int).SetBytes([]byte{1, 2, 3, 4})
	s := new(big.Int).SetBytes([]byte{5, 6, 7, 8})
	sigBytes := make([]byte, 64)
	r.FillBytes(sigBytes[:32])
	s.FillBytes(sigBytes[32:])
	sig.Signature = sigBytes

	keys := map[uint16]DNSKEY{KeyTag(key): key}
	if err := VerifyRRSIG(keys, makeRRset(), sig, nil); err == nil {
		t.Fatal("expected error for bad signature")
	}
}

func TestVerifyRRSIG_Expired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	key := DNSKEY{Flags: 256, Protocol: 3, Algorithm: AlgED25519, PublicKey: []byte(pub)}
	now := uint32(time.Now().Unix())
	sig := RRSIG{
		TypeCovered: dns.TypeA,
		Algorithm:   AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  now - 1,
		Inception:   now - 7200,
		KeyTag:      KeyTag(key),
		SignerName:  "example.com",
	}
	rrset := makeRRset()
	sig.Signature = ed25519.Sign(priv, buildSignedData(sig, rrset, nil))

	keys := map[uint16]DNSKEY{KeyTag(key): key}
	if err := VerifyRRSIG(keys, rrset, sig, nil); err == nil {
		t.Fatal("expected error for expired RRSIG")
	}
}

func TestVerifyRRSIG_NotYetValid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	key := DNSKEY{Flags: 256, Protocol: 3, Algorithm: AlgED25519, PublicKey: []byte(pub)}
	now := uint32(time.Now().Unix())
	sig := RRSIG{
		TypeCovered: dns.TypeA,
		Algorithm:   AlgED25519,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  now + 7200,
		Inception:   now + 3600,
		KeyTag:      KeyTag(key),
		SignerName:  "example.com",
	}
	rrset := makeRRset()
	sig.Signature = ed25519.Sign(priv, buildSignedData(sig, rrset, nil))

	keys := map[uint16]DNSKEY{KeyTag(key): key}
	if err := VerifyRRSIG(keys, rrset, sig, nil); err == nil {
		t.Fatal("expected error for not-yet-valid RRSIG")
	}
}

func TestVerifyRRSIG_MissingKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	key := DNSKEY{Flags: 256, Protocol: 3, Algorithm: AlgED25519, PublicKey: []byte(pub)}
	rrset := makeRRset()
	sig := makeRRSIGBase(AlgED25519, KeyTag(key))
	sig.Signature = ed25519.Sign(priv, buildSignedData(sig, rrset, nil))

	if err := VerifyRRSIG(map[uint16]DNSKEY{}, rrset, sig, nil); err == nil {
		t.Fatal("expected error when key is absent from map")
	}
}

func TestValidatorCache(t *testing.T) {
	v := NewValidator()

	key := DNSKEY{Flags: 256, Protocol: 3, Algorithm: AlgED25519, PublicKey: make([]byte, 32)}
	keys := map[uint16]DNSKEY{KeyTag(key): key}

	if got := v.LookupZoneKeys("example.com"); got != nil {
		t.Fatal("expected nil before caching")
	}

	v.CacheZoneKeys("example.com", keys, 60)

	got := v.LookupZoneKeys("example.com")
	if got == nil {
		t.Fatal("expected cached keys")
	}
	if _, ok := got[KeyTag(key)]; !ok {
		t.Error("cached key not found")
	}

	if v.LookupZoneKeys("EXAMPLE.COM") == nil {
		t.Error("cache lookup should be case-insensitive")
	}

	v.CacheZoneKeys("sub.example.com.", keys, 60)
	if v.LookupZoneKeys("sub.example.com") == nil {
		t.Error("cache should normalise trailing dot")
	}
}

func TestValidatorCache_DefaultTTL(t *testing.T) {
	v := NewValidator()
	key := DNSKEY{Flags: 256, Protocol: 3, Algorithm: AlgED25519, PublicKey: make([]byte, 32)}
	v.CacheZoneKeys("example.com", map[uint16]DNSKEY{KeyTag(key): key}, 0)
	if v.LookupZoneKeys("example.com") == nil {
		t.Fatal("zero TTL should use default, not expire immediately")
	}
}

func TestNewValidator_HasRootAnchors(t *testing.T) {
	v := NewValidator()
	if _, ok := v.anchors[20326]; !ok {
		t.Error("KSK-2017 (20326) not loaded")
	}
	if _, ok := v.anchors[38696]; !ok {
		t.Error("KSK-2024 (38696) not loaded")
	}
}
