package dnssec

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kohanmathers/kmresolv/internal/dns"
)

const (
	AlgRSASHA1          = 5
	AlgRSASHA1NSEC3SHA1 = 7
	AlgRSASHA256        = 8
	AlgRSASHA512        = 10
	AlgECDSAP256SHA256  = 13
	AlgECDSAP384SHA384  = 14
	AlgED25519          = 15
)

const (
	DigestTypeSHA1   = 1
	DigestTypeSHA256 = 2
	DigestTypeSHA384 = 4
)

type ValidationStatus int

const (
	StatusSecure ValidationStatus = iota
	StatusInsecure
	StatusBogus
)

type DNSKEY struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey []byte
}

type DS struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

type RRSIG struct {
	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	OrigTTL     uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  string
	Signature   []byte
}

func ParseDNSKEY(rr dns.RR) (DNSKEY, error) {
	if rr.Type != dns.TypeDNSKEY {
		return DNSKEY{}, fmt.Errorf("not a DNSKEY record (type %d)", rr.Type)
	}
	if len(rr.Data) < 4 {
		return DNSKEY{}, errors.New("DNSKEY rdata too short")
	}
	return DNSKEY{
		Flags:     binary.BigEndian.Uint16(rr.Data[0:2]),
		Protocol:  rr.Data[2],
		Algorithm: rr.Data[3],
		PublicKey: append([]byte(nil), rr.Data[4:]...),
	}, nil
}

func ParseDS(rr dns.RR) (DS, error) {
	if rr.Type != dns.TypeDS {
		return DS{}, fmt.Errorf("not a DS record (type %d)", rr.Type)
	}
	if len(rr.Data) < 4 {
		return DS{}, errors.New("DS rdata too short")
	}
	return DS{
		KeyTag:     binary.BigEndian.Uint16(rr.Data[0:2]),
		Algorithm:  rr.Data[2],
		DigestType: rr.Data[3],
		Digest:     append([]byte(nil), rr.Data[4:]...),
	}, nil
}

func ParseRRSIG(rr dns.RR) (RRSIG, error) {
	if rr.Type != dns.TypeRRSIG {
		return RRSIG{}, fmt.Errorf("not an RRSIG record (type %d)", rr.Type)
	}
	data := rr.Data
	if len(data) < 18 {
		return RRSIG{}, errors.New("RRSIG rdata too short")
	}
	r := RRSIG{
		TypeCovered: binary.BigEndian.Uint16(data[0:2]),
		Algorithm:   data[2],
		Labels:      data[3],
		OrigTTL:     binary.BigEndian.Uint32(data[4:8]),
		Expiration:  binary.BigEndian.Uint32(data[8:12]),
		Inception:   binary.BigEndian.Uint32(data[12:16]),
		KeyTag:      binary.BigEndian.Uint16(data[16:18]),
	}
	signerName, n, err := parseUncompressedName(data[18:])
	if err != nil {
		return RRSIG{}, fmt.Errorf("RRSIG signer name: %w", err)
	}
	r.SignerName = signerName
	r.Signature = append([]byte(nil), data[18+n:]...)
	return r, nil
}

func KeyTag(k DNSKEY) uint16 {
	if k.Algorithm == 1 {
		n := len(k.PublicKey)
		if n < 2 {
			return 0
		}
		return binary.BigEndian.Uint16(k.PublicKey[n-2:])
	}
	rdata := dnskeyRdata(k)
	var sum uint32
	for i, b := range rdata {
		if i&1 == 0 {
			sum += uint32(b) << 8
		} else {
			sum += uint32(b)
		}
	}
	sum += sum >> 16
	return uint16(sum & 0xFFFF)
}

func VerifyDS(zoneName string, key DNSKEY, ds DS) error {
	if KeyTag(key) != ds.KeyTag {
		return fmt.Errorf("key tag mismatch: dnskey=%d ds=%d", KeyTag(key), ds.KeyTag)
	}
	if key.Algorithm != ds.Algorithm {
		return fmt.Errorf("algorithm mismatch: dnskey=%d ds=%d", key.Algorithm, ds.Algorithm)
	}

	input := append(WireName(zoneName), dnskeyRdata(key)...)

	var digest []byte
	switch ds.DigestType {
	case DigestTypeSHA1:
		h := sha1.Sum(input)
		digest = h[:]
	case DigestTypeSHA256:
		h := sha256.Sum256(input)
		digest = h[:]
	case DigestTypeSHA384:
		h := sha512.Sum384(input)
		digest = h[:]
	default:
		return fmt.Errorf("unsupported DS digest type: %d", ds.DigestType)
	}

	if !bytes.Equal(digest, ds.Digest) {
		return errors.New("DS digest mismatch")
	}
	return nil
}

func VerifyRRSIG(keys map[uint16]DNSKEY, rrset []dns.RR, sig RRSIG, raw []byte) error {
	now := uint32(time.Now().Unix())
	if now < sig.Inception {
		return fmt.Errorf("RRSIG not yet valid (inception %d)", sig.Inception)
	}
	if now > sig.Expiration {
		return fmt.Errorf("RRSIG expired (expiration %d)", sig.Expiration)
	}

	key, ok := keys[sig.KeyTag]
	if !ok {
		return fmt.Errorf("no DNSKEY with tag %d", sig.KeyTag)
	}
	if key.Algorithm != sig.Algorithm {
		return fmt.Errorf("algorithm mismatch: key=%d sig=%d", key.Algorithm, sig.Algorithm)
	}

	signed := buildSignedData(sig, rrset, raw)
	return verifyCrypto(key, signed, sig.Signature)
}

func VerifyAnyRRSIG(keys map[uint16]DNSKEY, rrset []dns.RR, rrsigs []dns.RR, typeCovered uint16, raw []byte) error {
	var lastErr error
	for _, rr := range rrsigs {
		if rr.Type != dns.TypeRRSIG {
			continue
		}
		sig, err := ParseRRSIG(rr)
		if err != nil {
			continue
		}
		if sig.TypeCovered != typeCovered {
			continue
		}
		err = VerifyRRSIG(keys, rrset, sig, raw)
		if err == nil {
			return nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("no RRSIG found covering type %d", typeCovered)
}

func (v *Validator) ValidateZoneDNSKEY(
	zoneName string,
	dnskeyRRs []dns.RR,
	rrsigRRs []dns.RR,
	parentDS []DS,
	raw []byte,
) (map[uint16]DNSKEY, error) {
	if len(dnskeyRRs) == 0 {
		return nil, errors.New("no DNSKEY records")
	}

	allKeys := make(map[uint16]DNSKEY)
	for _, rr := range dnskeyRRs {
		if rr.Type != dns.TypeDNSKEY {
			continue
		}
		k, err := ParseDNSKEY(rr)
		if err != nil {
			continue
		}
		allKeys[KeyTag(k)] = k
	}

	trustSeeds := make(map[uint16]DNSKEY)
	if isRootZone(zoneName) {
		for tag, anchor := range v.anchors {
			if _, ok := allKeys[tag]; ok {
				trustSeeds[tag] = anchor
			}
			for _, k := range allKeys {
				if KeyTag(k) == tag {
					trustSeeds[tag] = k
				}
			}
		}
		if len(trustSeeds) == 0 {
			return nil, errors.New("root DNSKEY RRset contains no key matching trust anchor")
		}
	} else {
		if len(parentDS) == 0 {
			return nil, errors.New("no DS records from parent zone")
		}
		for _, ds := range parentDS {
			k, ok := allKeys[ds.KeyTag]
			if !ok {
				continue
			}
			if err := VerifyDS(zoneName, k, ds); err != nil {
				continue
			}
			trustSeeds[ds.KeyTag] = k
		}
		if len(trustSeeds) == 0 {
			return nil, errors.New("no DNSKEY in RRset matched parent DS records")
		}
	}

	if err := VerifyAnyRRSIG(trustSeeds, dnskeyRRs, rrsigRRs, dns.TypeDNSKEY, raw); err != nil {
		return nil, fmt.Errorf("DNSKEY RRset RRSIG: %w", err)
	}

	return allKeys, nil
}

type Validator struct {
	anchors  map[uint16]DNSKEY
	keyCache sync.Map
}

type cachedZone struct {
	keys      map[uint16]DNSKEY
	expiresAt time.Time
}

func NewValidator() *Validator {
	v := &Validator{anchors: make(map[uint16]DNSKEY)}
	for _, a := range rootTrustAnchors() {
		v.anchors[KeyTag(a)] = a
	}
	return v
}

func (v *Validator) CacheZoneKeys(zone string, keys map[uint16]DNSKEY, ttl uint32) {
	if ttl == 0 {
		ttl = 3600
	}
	v.keyCache.Store(strings.ToLower(fqdn(zone)), &cachedZone{
		keys:      keys,
		expiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	})
}

func (v *Validator) LookupZoneKeys(zone string) map[uint16]DNSKEY {
	val, ok := v.keyCache.Load(strings.ToLower(fqdn(zone)))
	if !ok {
		return nil
	}
	cz := val.(*cachedZone)
	if time.Now().After(cz.expiresAt) {
		v.keyCache.Delete(strings.ToLower(fqdn(zone)))
		return nil
	}
	return cz.keys
}

func rootTrustAnchors() []DNSKEY {
	const ksk2017 = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3" +
		"+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv" +
		"ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0" +
		"jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZ" +
		"G+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRU" +
		"fhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1A" +
		"kUTV74bU="

	const ksk2024 = "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/c" +
		"idltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbG" +
		"iShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFU" +
		"iRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwu" +
		"MoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2" +
		"CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC" +
		"73PYc="

	decode := func(s, name string) []byte {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			panic("root trust anchor " + name + ": invalid base64: " + err.Error())
		}
		return b
	}
	return []DNSKEY{
		{Flags: 257, Protocol: 3, Algorithm: AlgRSASHA256, PublicKey: decode(ksk2017, "ksk2017")},
		{Flags: 257, Protocol: 3, Algorithm: AlgRSASHA256, PublicKey: decode(ksk2024, "ksk2024")},
	}
}

func WireName(name string) []byte {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return []byte{0}
	}
	var buf []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0)
	return buf
}

func buildSignedData(sig RRSIG, rrset []dns.RR, raw []byte) []byte {
	signerWire := WireName(sig.SignerName)

	hdr := make([]byte, 18+len(signerWire))
	binary.BigEndian.PutUint16(hdr[0:], sig.TypeCovered)
	hdr[2] = sig.Algorithm
	hdr[3] = sig.Labels
	binary.BigEndian.PutUint32(hdr[4:], sig.OrigTTL)
	binary.BigEndian.PutUint32(hdr[8:], sig.Expiration)
	binary.BigEndian.PutUint32(hdr[12:], sig.Expiration)
	binary.BigEndian.PutUint32(hdr[8:], sig.Expiration)
	binary.BigEndian.PutUint32(hdr[12:], sig.Inception)
	binary.BigEndian.PutUint16(hdr[16:], sig.KeyTag)
	copy(hdr[18:], signerWire)

	ownerName := strings.ToLower(rrset[0].Name)
	ownerLabels := labelCount(ownerName)
	if int(sig.Labels) < ownerLabels {
		parts := strings.SplitN(ownerName, ".", ownerLabels-int(sig.Labels)+1)
		ownerName = "*." + parts[len(parts)-1]
	}
	ownerWire := WireName(ownerName)

	type item struct{ rdata, full []byte }
	items := make([]item, 0, len(rrset))
	for _, rr := range rrset {
		rdata := canonRdata(rr, raw)
		full := make([]byte, len(ownerWire)+10+len(rdata))
		off := copy(full, ownerWire)
		binary.BigEndian.PutUint16(full[off:], rr.Type)
		off += 2
		binary.BigEndian.PutUint16(full[off:], dns.ClassIN)
		off += 2
		binary.BigEndian.PutUint32(full[off:], sig.OrigTTL)
		off += 4
		binary.BigEndian.PutUint16(full[off:], uint16(len(rdata)))
		off += 2
		copy(full[off:], rdata)
		items = append(items, item{rdata: rdata, full: full})
	}
	sort.Slice(items, func(i, j int) bool {
		return bytes.Compare(items[i].rdata, items[j].rdata) < 0
	})

	var buf []byte
	buf = append(buf, hdr...)
	for _, it := range items {
		buf = append(buf, it.full...)
	}
	return buf
}

func canonRdata(rr dns.RR, raw []byte) []byte {
	switch rr.Type {
	case dns.TypeNS, dns.TypeCNAME, dns.TypePTR:
		name, _, err := dns.ParseName(raw, rr.Offset)
		if err != nil {
			return rr.Data
		}
		return WireName(name)

	case dns.TypeMX:
		if len(rr.Data) < 2 {
			return rr.Data
		}
		name, _, err := dns.ParseName(raw, rr.Offset+2)
		if err != nil {
			return rr.Data
		}
		result := make([]byte, 2)
		copy(result, rr.Data[:2])
		return append(result, WireName(name)...)

	case dns.TypeSOA:
		mname, n1, err := dns.ParseName(raw, rr.Offset)
		if err != nil {
			return rr.Data
		}
		rname, n2, err := dns.ParseName(raw, n1)
		if err != nil {
			return rr.Data
		}
		result := append(WireName(mname), WireName(rname)...)
		return append(result, rr.Data[n2-rr.Offset:]...)

	case dns.TypeSRV:
		if len(rr.Data) < 6 {
			return rr.Data
		}
		name, _, err := dns.ParseName(raw, rr.Offset+6)
		if err != nil {
			return rr.Data
		}
		return append(append([]byte(nil), rr.Data[:6]...), WireName(name)...)

	case dns.TypeNAPTR:
		return rr.Data

	default:
		return rr.Data
	}
}

func verifyCrypto(key DNSKEY, data, signature []byte) error {
	switch key.Algorithm {
	case AlgRSASHA1, AlgRSASHA1NSEC3SHA1:
		return verifyRSA(key.PublicKey, data, signature, crypto.SHA1)
	case AlgRSASHA256:
		return verifyRSA(key.PublicKey, data, signature, crypto.SHA256)
	case AlgRSASHA512:
		return verifyRSA(key.PublicKey, data, signature, crypto.SHA512)
	case AlgECDSAP256SHA256:
		return verifyECDSAP256(key.PublicKey, data, signature)
	case AlgECDSAP384SHA384:
		return verifyECDSAP384(key.PublicKey, data, signature)
	case AlgED25519:
		return verifyED25519(key.PublicKey, data, signature)
	default:
		return fmt.Errorf("unsupported algorithm: %d", key.Algorithm)
	}
}

func verifyRSA(pubKeyData, data, signature []byte, hash crypto.Hash) error {
	pub, err := parseRSAPublicKey(pubKeyData)
	if err != nil {
		return err
	}
	h := hash.New()
	h.Write(data)
	return rsa.VerifyPKCS1v15(pub, hash, h.Sum(nil), signature)
}

func parseRSAPublicKey(data []byte) (*rsa.PublicKey, error) {
	if len(data) < 2 {
		return nil, errors.New("RSA public key too short")
	}
	var eLen, off int
	if data[0] == 0 {
		if len(data) < 3 {
			return nil, errors.New("RSA exponent length field truncated")
		}
		eLen = int(binary.BigEndian.Uint16(data[1:3]))
		off = 3
	} else {
		eLen = int(data[0])
		off = 1
	}
	if len(data) < off+eLen+1 {
		return nil, errors.New("RSA key data truncated")
	}
	e := new(big.Int).SetBytes(data[off : off+eLen])
	n := new(big.Int).SetBytes(data[off+eLen:])
	if !e.IsInt64() {
		return nil, errors.New("RSA exponent overflows int64")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func verifyECDSAP256(pubKeyData, data, signature []byte) error {
	if len(pubKeyData) != 64 {
		return fmt.Errorf("ECDSA P-256 public key: want 64 bytes, got %d", len(pubKeyData))
	}
	if len(signature) != 64 {
		return fmt.Errorf("ECDSA P-256 signature: want 64 bytes, got %d", len(signature))
	}
	x := new(big.Int).SetBytes(pubKeyData[:32])
	y := new(big.Int).SetBytes(pubKeyData[32:])
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	h := sha256.Sum256(data)
	if !ecdsa.Verify(pub, h[:], r, s) {
		return errors.New("ECDSA P-256 signature verification failed")
	}
	return nil
}

func verifyECDSAP384(pubKeyData, data, signature []byte) error {
	if len(pubKeyData) != 96 {
		return fmt.Errorf("ECDSA P-384 public key: want 96 bytes, got %d", len(pubKeyData))
	}
	if len(signature) != 96 {
		return fmt.Errorf("ECDSA P-384 signature: want 96 bytes, got %d", len(signature))
	}
	x := new(big.Int).SetBytes(pubKeyData[:48])
	y := new(big.Int).SetBytes(pubKeyData[48:])
	pub := &ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}
	r := new(big.Int).SetBytes(signature[:48])
	s := new(big.Int).SetBytes(signature[48:])
	h := sha512.Sum384(data)
	if !ecdsa.Verify(pub, h[:], r, s) {
		return errors.New("ECDSA P-384 signature verification failed")
	}
	return nil
}

func verifyED25519(pubKeyData, data, signature []byte) error {
	if len(pubKeyData) != ed25519.PublicKeySize {
		return fmt.Errorf("Ed25519 public key: want %d bytes, got %d", ed25519.PublicKeySize, len(pubKeyData))
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("Ed25519 signature: want %d bytes, got %d", ed25519.SignatureSize, len(signature))
	}
	if !ed25519.Verify(ed25519.PublicKey(pubKeyData), data, signature) {
		return errors.New("Ed25519 signature verification failed")
	}
	return nil
}

func dnskeyRdata(k DNSKEY) []byte {
	buf := make([]byte, 4+len(k.PublicKey))
	binary.BigEndian.PutUint16(buf[0:], k.Flags)
	buf[2] = k.Protocol
	buf[3] = k.Algorithm
	copy(buf[4:], k.PublicKey)
	return buf
}

func parseUncompressedName(data []byte) (string, int, error) {
	var labels []string
	i := 0
	for {
		if i >= len(data) {
			return "", 0, errors.New("name parse: unexpected end of data")
		}
		l := int(data[i])
		i++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 {
			return "", 0, fmt.Errorf("name parse: unexpected flag bits 0x%02x (no compression in this context)", data[i-1])
		}
		if i+l > len(data) {
			return "", 0, errors.New("name parse: label out of bounds")
		}
		labels = append(labels, strings.ToLower(string(data[i:i+l])))
		i += l
	}
	if len(labels) == 0 {
		return ".", i, nil
	}
	return strings.Join(labels, "."), i, nil
}

func isRootZone(name string) bool {
	return name == "." || name == ""
}

func fqdn(name string) string {
	if !strings.HasSuffix(name, ".") {
		return name + "."
	}
	return name
}

func labelCount(name string) int {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return 0
	}
	return strings.Count(name, ".") + 1
}
