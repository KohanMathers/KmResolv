package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	TypeA          = 1
	TypeNS         = 2
	TypeCNAME      = 5
	TypeSOA        = 6
	TypePTR        = 12
	TypeMX         = 15
	TypeTXT        = 16
	TypeAAAA       = 28
	TypeLOC        = 29
	TypeSRV        = 33
	TypeNAPTR      = 35
	TypeCERT       = 37
	TypeDS         = 43
	TypeSSHFP      = 44
	TypeRRSIG      = 46
	TypeNSEC       = 47
	TypeDNSKEY     = 48
	TypeNSEC3      = 50
	TypeTLSA       = 52
	TypeSMIMEA     = 53
	TypeOPENPGPKEY = 61
	TypeSVCB       = 64
	TypeHTTPS      = 65
	TypeURI        = 256
	TypeCAA        = 257
	ClassIN        = 1
)

const (
	RcodeNoError  = 0
	RcodeServFail = 2
	RcodeNXDomain = 3
)

type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func (h *Header) QR() bool          { return h.Flags&0x8000 != 0 }
func (h *Header) SetQR(v bool)      { setBit(&h.Flags, 15, v) }
func (h *Header) SetAA(v bool)      { setBit(&h.Flags, 10, v) }
func (h *Header) SetRD(v bool)      { setBit(&h.Flags, 8, v) }
func (h *Header) SetRA(v bool)      { setBit(&h.Flags, 7, v) }
func (h *Header) SetAD(v bool)      { setBit(&h.Flags, 5, v) }
func (h *Header) Rcode() uint16     { return h.Flags & 0x000F }
func (h *Header) SetRcode(r uint16) { h.Flags = (h.Flags &^ 0x000F) | (r & 0x000F) }
func (h *Header) RD() bool          { return h.Flags&0x0100 != 0 }

func setBit(f *uint16, bit uint, v bool) {
	if v {
		*f |= 1 << bit
	} else {
		*f &^= 1 << bit
	}
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

type RR struct {
	Name   string
	Type   uint16
	Class  uint16
	TTL    uint32
	Data   []byte
	Offset int
}

type Message struct {
	Header
	Questions  []Question
	Answers    []RR
	Authority  []RR
	Additional []RR
	Raw        []byte
}

func ParseMessage(buf []byte) (*Message, error) {
	if len(buf) < 12 {
		return nil, errors.New("message too short")
	}
	m := &Message{}
	m.Raw = append([]byte(nil), buf...)
	m.ID = binary.BigEndian.Uint16(buf[0:2])
	m.Flags = binary.BigEndian.Uint16(buf[2:4])
	m.QDCount = binary.BigEndian.Uint16(buf[4:6])
	m.ANCount = binary.BigEndian.Uint16(buf[6:8])
	m.NSCount = binary.BigEndian.Uint16(buf[8:10])
	m.ARCount = binary.BigEndian.Uint16(buf[10:12])

	offset := 12

	for i := 0; i < int(m.QDCount); i++ {
		name, n, err := parseName(buf, offset)
		if err != nil {
			return nil, fmt.Errorf("question name: %w", err)
		}
		offset = n
		if offset+4 > len(buf) {
			return nil, errors.New("question section truncated")
		}
		m.Questions = append(m.Questions, Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(buf[offset : offset+2]),
			Class: binary.BigEndian.Uint16(buf[offset+2 : offset+4]),
		})
		offset += 4
	}

	var err error
	m.Answers, offset, err = parseRRs(m.Raw, offset, int(m.ANCount))
	if err != nil {
		return nil, err
	}
	m.Authority, offset, err = parseRRs(m.Raw, offset, int(m.NSCount))
	if err != nil {
		return nil, err
	}
	m.Additional, _, err = parseRRs(m.Raw, offset, int(m.ARCount))
	return m, err
}

func parseRRs(buf []byte, offset, count int) ([]RR, int, error) {
	rrs := make([]RR, 0, count)
	for i := 0; i < count; i++ {
		name, n, err := parseName(buf, offset)
		if err != nil {
			return nil, 0, fmt.Errorf("rr name: %w", err)
		}
		offset = n
		if offset+10 > len(buf) {
			return nil, 0, errors.New("rr fixed fields truncated")
		}
		rtype := binary.BigEndian.Uint16(buf[offset : offset+2])
		rclass := binary.BigEndian.Uint16(buf[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(buf[offset+4 : offset+8])
		rdlen := int(binary.BigEndian.Uint16(buf[offset+8 : offset+10]))
		offset += 10
		if offset+rdlen > len(buf) {
			return nil, 0, errors.New("rdata truncated")
		}
		rrs = append(rrs, RR{
			Name:   name,
			Type:   rtype,
			Class:  rclass,
			TTL:    ttl,
			Data:   buf[offset : offset+rdlen],
			Offset: offset,
		})
		offset += rdlen
	}
	return rrs, offset, nil
}

func parseName(buf []byte, offset int) (string, int, error) {
	var name []byte
	visited := make(map[int]bool)
	end := -1

	for {
		if offset >= len(buf) {
			return "", 0, errors.New("name parse: offset out of bounds")
		}
		length := int(buf[offset])

		if length == 0 {
			if end == -1 {
				end = offset + 1
			}
			break
		}

		if length&0xC0 == 0xC0 {
			if offset+1 >= len(buf) {
				return "", 0, errors.New("name parse: pointer truncated")
			}
			if end == -1 {
				end = offset + 2
			}
			ptr := int(binary.BigEndian.Uint16(buf[offset:offset+2]) & 0x3FFF)
			if visited[ptr] {
				return "", 0, errors.New("name parse: compression pointer loop")
			}
			visited[ptr] = true
			offset = ptr
			continue
		}

		if length&0xC0 != 0 {
			return "", 0, fmt.Errorf("name parse: reserved label type 0x%x", length)
		}

		offset++
		if offset+length > len(buf) {
			return "", 0, errors.New("name parse: label out of bounds")
		}
		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, buf[offset:offset+length]...)
		offset += length
	}

	return string(name), end, nil
}

func (m *Message) Pack() ([]byte, error) {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], m.ID)
	binary.BigEndian.PutUint16(buf[2:4], m.Flags)
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(m.Questions)))
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(m.Answers)))
	binary.BigEndian.PutUint16(buf[8:10], uint16(len(m.Authority)))
	binary.BigEndian.PutUint16(buf[10:12], uint16(len(m.Additional)))

	for _, q := range m.Questions {
		buf = append(buf, packName(q.Name)...)
		buf = append(buf, 0, 0, 0, 0)
		binary.BigEndian.PutUint16(buf[len(buf)-4:], q.Type)
		binary.BigEndian.PutUint16(buf[len(buf)-2:], q.Class)
	}

	for _, section := range [][]RR{m.Answers, m.Authority, m.Additional} {
		for _, rr := range section {
			buf = append(buf, packName(rr.Name)...)
			rdata := packRdata(rr, m.Raw)
			fixed := make([]byte, 10)
			binary.BigEndian.PutUint16(fixed[0:2], rr.Type)
			binary.BigEndian.PutUint16(fixed[2:4], rr.Class)
			binary.BigEndian.PutUint32(fixed[4:8], rr.TTL)
			binary.BigEndian.PutUint16(fixed[8:10], uint16(len(rdata)))
			buf = append(buf, fixed...)
			buf = append(buf, rdata...)
		}
	}
	return buf, nil
}

func PackName(name string) []byte { return packName(name) }

func ParseName(buf []byte, offset int) (string, int, error) { return parseName(buf, offset) }

func packName(name string) []byte {
	if name == "" || name == "." {
		return []byte{0}
	}
	var buf []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			buf = append(buf, byte(len(label)))
			buf = append(buf, label...)
			start = i + 1
		}
	}
	buf = append(buf, 0)
	return buf
}

func packRdata(rr RR, raw []byte) []byte {
	switch rr.Type {
	case TypeNS, TypeCNAME, TypeMX, TypePTR:
		nameOffset := rr.Offset
		if rr.Type == TypeMX {
			nameOffset += 2
		}
		if raw != nil && nameOffset < len(raw) {
			name, _, err := parseName(raw, nameOffset)
			if err == nil {
				if rr.Type == TypeMX {
					pref := rr.Data[:2]
					return append(pref, packName(name)...)
				}
				return packName(name)
			}
		}
	}
	return rr.Data
}

func ParseA(data []byte) (string, error) {
	if len(data) != 4 {
		return "", fmt.Errorf("A rdata wrong length: %d", len(data))
	}
	return fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3]), nil
}

func ParseNameRdata(packet, rdata []byte, offset int) (string, error) {
	name, _, err := parseName(packet, offset)
	return name, err
}
