package records

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
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

func ValidateRecord(r config.RecordConfig) error {
	_, err := buildRR(r)
	return err
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

	case "PTR":
		rr.Type = dns.TypePTR
		rr.Data = dns.PackName(r.Value)

	case "NS":
		rr.Type = dns.TypeNS
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

	case "SRV":
		parts := strings.Fields(r.Value)
		if len(parts) != 4 {
			return dns.RR{}, fmt.Errorf("SRV value must be \"<priority> <weight> <port> <target>\": %s", r.Value)
		}
		prio, err := parseUint16(parts[0], "SRV priority")
		if err != nil {
			return dns.RR{}, err
		}
		weight, err := parseUint16(parts[1], "SRV weight")
		if err != nil {
			return dns.RR{}, err
		}
		port, err := parseUint16(parts[2], "SRV port")
		if err != nil {
			return dns.RR{}, err
		}
		hdr := make([]byte, 6)
		binary.BigEndian.PutUint16(hdr[0:], prio)
		binary.BigEndian.PutUint16(hdr[2:], weight)
		binary.BigEndian.PutUint16(hdr[4:], port)
		rr.Type = dns.TypeSRV
		rr.Data = append(hdr, dns.PackName(parts[3])...)

	case "CAA":
		parts := strings.SplitN(r.Value, " ", 3)
		if len(parts) != 3 {
			return dns.RR{}, fmt.Errorf("CAA value must be \"<flags> <tag> <value>\": %s", r.Value)
		}
		flags, err := strconv.ParseUint(parts[0], 10, 8)
		if err != nil {
			return dns.RR{}, fmt.Errorf("CAA flags: %w", err)
		}
		tag := []byte(parts[1])
		val := []byte(parts[2])
		rr.Type = dns.TypeCAA
		rr.Data = append([]byte{byte(flags), byte(len(tag))}, append(tag, val...)...)

	case "CERT":
		parts := strings.Fields(r.Value)
		if len(parts) != 4 {
			return dns.RR{}, fmt.Errorf("CERT value must be \"<cert_type> <key_tag> <algorithm> <base64>\": %s", r.Value)
		}
		certType, err := parseUint16(parts[0], "CERT type")
		if err != nil {
			return dns.RR{}, err
		}
		keyTag, err := parseUint16(parts[1], "CERT key_tag")
		if err != nil {
			return dns.RR{}, err
		}
		alg, err := parseUint8(parts[2], "CERT algorithm")
		if err != nil {
			return dns.RR{}, err
		}
		certData, err := base64.StdEncoding.DecodeString(parts[3])
		if err != nil {
			return dns.RR{}, fmt.Errorf("CERT base64: %w", err)
		}
		hdr := make([]byte, 5)
		binary.BigEndian.PutUint16(hdr[0:], certType)
		binary.BigEndian.PutUint16(hdr[2:], keyTag)
		hdr[4] = alg
		rr.Type = dns.TypeCERT
		rr.Data = append(hdr, certData...)

	case "DNSKEY":
		parts := strings.Fields(r.Value)
		if len(parts) != 4 {
			return dns.RR{}, fmt.Errorf("DNSKEY value must be \"<flags> <protocol> <algorithm> <base64>\": %s", r.Value)
		}
		flags, err := parseUint16(parts[0], "DNSKEY flags")
		if err != nil {
			return dns.RR{}, err
		}
		proto, err := parseUint8(parts[1], "DNSKEY protocol")
		if err != nil {
			return dns.RR{}, err
		}
		alg, err := parseUint8(parts[2], "DNSKEY algorithm")
		if err != nil {
			return dns.RR{}, err
		}
		keyData, err := base64.StdEncoding.DecodeString(parts[3])
		if err != nil {
			return dns.RR{}, fmt.Errorf("DNSKEY base64: %w", err)
		}
		hdr := []byte{0, 0, proto, alg}
		binary.BigEndian.PutUint16(hdr[0:], flags)
		rr.Type = dns.TypeDNSKEY
		rr.Data = append(hdr, keyData...)

	case "DS":
		parts := strings.Fields(r.Value)
		if len(parts) != 4 {
			return dns.RR{}, fmt.Errorf("DS value must be \"<key_tag> <algorithm> <digest_type> <hex_digest>\": %s", r.Value)
		}
		keyTag, err := parseUint16(parts[0], "DS key_tag")
		if err != nil {
			return dns.RR{}, err
		}
		alg, err := parseUint8(parts[1], "DS algorithm")
		if err != nil {
			return dns.RR{}, err
		}
		digestType, err := parseUint8(parts[2], "DS digest_type")
		if err != nil {
			return dns.RR{}, err
		}
		digest, err := hex.DecodeString(parts[3])
		if err != nil {
			return dns.RR{}, fmt.Errorf("DS digest hex: %w", err)
		}
		hdr := []byte{0, 0, alg, digestType}
		binary.BigEndian.PutUint16(hdr[0:], keyTag)
		rr.Type = dns.TypeDS
		rr.Data = append(hdr, digest...)

	case "HTTPS", "SVCB":
		parts := strings.SplitN(r.Value, " ", 2)
		if len(parts) != 2 {
			return dns.RR{}, fmt.Errorf("%s value must be \"<priority> <target>\": %s", strings.ToUpper(r.Type), r.Value)
		}
		prio, err := parseUint16(parts[0], strings.ToUpper(r.Type)+" priority")
		if err != nil {
			return dns.RR{}, err
		}
		target := strings.Fields(parts[1])[0]
		hdr := make([]byte, 2)
		binary.BigEndian.PutUint16(hdr, prio)
		if strings.ToUpper(r.Type) == "HTTPS" {
			rr.Type = dns.TypeHTTPS
		} else {
			rr.Type = dns.TypeSVCB
		}
		rr.Data = append(hdr, dns.PackName(target)...)

	case "LOC":
		data, err := parseLOC(r.Value)
		if err != nil {
			return dns.RR{}, err
		}
		rr.Type = dns.TypeLOC
		rr.Data = data

	case "NAPTR":
		parts := strings.Fields(r.Value)
		if len(parts) < 6 {
			return dns.RR{}, fmt.Errorf("NAPTR value must be \"<order> <preference> <flags> <service> <regexp> <replacement>\": %s", r.Value)
		}
		order, err := parseUint16(parts[0], "NAPTR order")
		if err != nil {
			return dns.RR{}, err
		}
		pref, err := parseUint16(parts[1], "NAPTR preference")
		if err != nil {
			return dns.RR{}, err
		}
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[0:], order)
		binary.BigEndian.PutUint16(hdr[2:], pref)
		data := hdr
		for _, s := range parts[2:5] {
			if s == "." {
				s = ""
			}
			data = append(data, byte(len(s)))
			data = append(data, []byte(s)...)
		}
		data = append(data, dns.PackName(parts[5])...)
		rr.Type = dns.TypeNAPTR
		rr.Data = data

	case "OPENPGPKEY":
		keyData, err := base64.StdEncoding.DecodeString(r.Value)
		if err != nil {
			return dns.RR{}, fmt.Errorf("OPENPGPKEY base64: %w", err)
		}
		rr.Type = dns.TypeOPENPGPKEY
		rr.Data = keyData

	case "SMIMEA":
		data, err := tlsaLike(r.Value, "SMIMEA")
		if err != nil {
			return dns.RR{}, err
		}
		rr.Type = dns.TypeSMIMEA
		rr.Data = data

	case "SSHFP":
		parts := strings.Fields(r.Value)
		if len(parts) != 3 {
			return dns.RR{}, fmt.Errorf("SSHFP value must be \"<algorithm> <fp_type> <hex_fingerprint>\": %s", r.Value)
		}
		alg, err := parseUint8(parts[0], "SSHFP algorithm")
		if err != nil {
			return dns.RR{}, err
		}
		fpType, err := parseUint8(parts[1], "SSHFP fingerprint_type")
		if err != nil {
			return dns.RR{}, err
		}
		fp, err := hex.DecodeString(parts[2])
		if err != nil {
			return dns.RR{}, fmt.Errorf("SSHFP fingerprint hex: %w", err)
		}
		rr.Type = dns.TypeSSHFP
		rr.Data = append([]byte{alg, fpType}, fp...)

	case "TLSA":
		data, err := tlsaLike(r.Value, "TLSA")
		if err != nil {
			return dns.RR{}, err
		}
		rr.Type = dns.TypeTLSA
		rr.Data = data

	case "URI":
		parts := strings.SplitN(r.Value, " ", 3)
		if len(parts) != 3 {
			return dns.RR{}, fmt.Errorf("URI value must be \"<priority> <weight> <target_uri>\": %s", r.Value)
		}
		prio, err := parseUint16(parts[0], "URI priority")
		if err != nil {
			return dns.RR{}, err
		}
		weight, err := parseUint16(parts[1], "URI weight")
		if err != nil {
			return dns.RR{}, err
		}
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[0:], prio)
		binary.BigEndian.PutUint16(hdr[2:], weight)
		rr.Type = dns.TypeURI
		rr.Data = append(hdr, []byte(parts[2])...)

	default:
		return dns.RR{}, fmt.Errorf("unsupported type: %s", r.Type)
	}
	return rr, nil
}

func tlsaLike(value, typeName string) ([]byte, error) {
	parts := strings.Fields(value)
	if len(parts) != 4 {
		return nil, fmt.Errorf("%s value must be \"<usage> <selector> <matching_type> <hex>\": %s", typeName, value)
	}
	usage, err := parseUint8(parts[0], typeName+" usage")
	if err != nil {
		return nil, err
	}
	sel, err := parseUint8(parts[1], typeName+" selector")
	if err != nil {
		return nil, err
	}
	mt, err := parseUint8(parts[2], typeName+" matching_type")
	if err != nil {
		return nil, err
	}
	cert, err := hex.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("%s cert data hex: %w", typeName, err)
	}
	return append([]byte{usage, sel, mt}, cert...), nil
}

func parseLOC(value string) ([]byte, error) {
	f := strings.Fields(value)
	i := 0

	get := func() (string, error) {
		if i >= len(f) {
			return "", fmt.Errorf("LOC: unexpected end of value")
		}
		s := f[i]
		i++
		return s, nil
	}
	isHemi := func(s string) bool {
		u := strings.ToUpper(s)
		return u == "N" || u == "S" || u == "E" || u == "W"
	}
	parseCoord := func(label string) (deg int, min int, secMs int64, hemi string, err error) {
		s, e := get()
		if e != nil {
			return 0, 0, 0, "", fmt.Errorf("LOC %s degrees: %w", label, e)
		}
		deg, err = strconv.Atoi(s)
		if err != nil {
			return 0, 0, 0, "", fmt.Errorf("LOC %s degrees: %w", label, err)
		}
		if i < len(f) && !isHemi(f[i]) {
			s, _ = get()
			min, err = strconv.Atoi(s)
			if err != nil {
				return 0, 0, 0, "", fmt.Errorf("LOC %s minutes: %w", label, err)
			}
			if i < len(f) && !isHemi(f[i]) {
				s, _ = get()
				sec, e2 := strconv.ParseFloat(s, 64)
				if e2 != nil {
					return 0, 0, 0, "", fmt.Errorf("LOC %s seconds: %w", label, e2)
				}
				secMs = int64(sec * 1000)
			}
		}
		s, e = get()
		if e != nil {
			return 0, 0, 0, "", fmt.Errorf("LOC %s hemisphere: %w", label, e)
		}
		hemi = strings.ToUpper(s)
		if !isHemi(hemi) {
			return 0, 0, 0, "", fmt.Errorf("LOC: expected hemisphere after %s, got %q", label, hemi)
		}
		return deg, min, secMs, hemi, nil
	}

	latD, latM, latSms, ns, err := parseCoord("latitude")
	if err != nil {
		return nil, err
	}
	lonD, lonM, lonSms, ew, err := parseCoord("longitude")
	if err != nil {
		return nil, err
	}

	altStr, err := get()
	if err != nil {
		return nil, fmt.Errorf("LOC altitude: %w", err)
	}
	altM, err := strconv.ParseFloat(strings.TrimSuffix(altStr, "m"), 64)
	if err != nil {
		return nil, fmt.Errorf("LOC altitude: %w", err)
	}

	sizeM, hpM, vpM := 1.0, 10000.0, 10.0
	if i < len(f) {
		s, _ := get()
		sizeM, err = strconv.ParseFloat(strings.TrimSuffix(s, "m"), 64)
		if err != nil {
			return nil, fmt.Errorf("LOC size: %w", err)
		}
		if i < len(f) {
			s, _ = get()
			hpM, err = strconv.ParseFloat(strings.TrimSuffix(s, "m"), 64)
			if err != nil {
				return nil, fmt.Errorf("LOC hp: %w", err)
			}
			if i < len(f) {
				s, _ = get()
				vpM, err = strconv.ParseFloat(strings.TrimSuffix(s, "m"), 64)
				if err != nil {
					return nil, fmt.Errorf("LOC vp: %w", err)
				}
			}
		}
	}

	const equatorial = uint32(0x80000000)
	latMs := uint32(int64(latD*3600+latM*60)*1000 + latSms)
	lonMs := uint32(int64(lonD*3600+lonM*60)*1000 + lonSms)

	var lat, lon uint32
	if ns == "N" {
		lat = equatorial + latMs
	} else {
		lat = equatorial - latMs
	}
	if ew == "E" {
		lon = equatorial + lonMs
	} else {
		lon = equatorial - lonMs
	}

	altCm := uint32(int64(altM*100) + 10000000)

	data := make([]byte, 16)
	data[0] = 0
	data[1] = locEncodeMeters(sizeM)
	data[2] = locEncodeMeters(hpM)
	data[3] = locEncodeMeters(vpM)
	binary.BigEndian.PutUint32(data[4:], lat)
	binary.BigEndian.PutUint32(data[8:], lon)
	binary.BigEndian.PutUint32(data[12:], altCm)
	return data, nil
}

func locEncodeMeters(m float64) byte {
	cm := int64(m*100 + 0.5)
	if cm <= 0 {
		return 0x00
	}
	exp := 0
	for cm >= 10 && exp < 9 {
		cm /= 10
		exp++
	}
	mant := cm
	if mant > 9 {
		mant = 9
	}
	if mant < 1 {
		mant = 1
	}
	return byte((mant << 4) | int64(exp))
}

func parseUint8(s, field string) (byte, error) {
	n, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", field, err)
	}
	return byte(n), nil
}

func parseUint16(s, field string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", field, err)
	}
	return uint16(n), nil
}
