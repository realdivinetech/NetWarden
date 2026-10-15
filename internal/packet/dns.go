package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
)

var ErrMalformedDNS = errors.New("malformed DNS message")

// DNS query types surfaced by the passive sniffer. Only address records are
// interpreted; other types are still reported with a zero IP.
const (
	DNSTypeA    = 1
	DNSTypeAAAA = 28
)

const (
	dnsFlagResponse = 0x8000
	dnsHeaderLength = 12
	dnsMaxNames     = 64
	dnsMaxJumps     = 32
	dnsMaxNameLen   = 255
)

type DNSQuestion struct {
	Name string
	Type uint16
}

type DNSAnswer struct {
	Name string
	Type uint16
	TTL  uint32
	IP   netip.Addr
}

// DNSMessage is the narrow, privacy-preserving view of a DNS packet: names and
// address records only. It intentionally ignores additional records and any
// other resource-record data.
type DNSMessage struct {
	ID        uint16
	Response  bool
	Questions []DNSQuestion
	Answers   []DNSAnswer
}

// ParseDNS parses a DNS message from a UDP/53 payload. It supports standard
// name compression, rejects malformed names and resource records, and never
// follows more than dnsMaxJumps compression pointers.
func ParseDNS(payload []byte) (DNSMessage, error) {
	if len(payload) < dnsHeaderLength {
		return DNSMessage{}, ErrMalformedDNS
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x7800 != 0 {
		// Opcodes other than standard QUERY are not passive-sniffable here.
		return DNSMessage{}, ErrMalformedDNS
	}
	message := DNSMessage{
		ID:       binary.BigEndian.Uint16(payload[0:2]),
		Response: flags&dnsFlagResponse != 0,
	}
	questionCount := int(binary.BigEndian.Uint16(payload[4:6]))
	answerCount := int(binary.BigEndian.Uint16(payload[6:8]))

	offset := dnsHeaderLength
	for i := 0; i < questionCount && i < dnsMaxNames; i++ {
		name, next, err := readDNSName(payload, offset)
		if err != nil {
			return DNSMessage{}, err
		}
		if next+4 > len(payload) {
			return DNSMessage{}, ErrMalformedDNS
		}
		message.Questions = append(message.Questions, DNSQuestion{
			Name: name,
			Type: binary.BigEndian.Uint16(payload[next : next+2]),
		})
		offset = next + 4
	}
	for i := 0; i < answerCount && i < dnsMaxNames; i++ {
		name, next, err := readDNSName(payload, offset)
		if err != nil {
			return DNSMessage{}, err
		}
		if next+10 > len(payload) {
			return DNSMessage{}, ErrMalformedDNS
		}
		recordType := binary.BigEndian.Uint16(payload[next : next+2])
		ttl := binary.BigEndian.Uint32(payload[next+4 : next+8])
		dataLength := int(binary.BigEndian.Uint16(payload[next+8 : next+10]))
		dataStart := next + 10
		if dataStart+dataLength > len(payload) {
			return DNSMessage{}, ErrMalformedDNS
		}
		answer := DNSAnswer{Name: name, Type: recordType, TTL: ttl}
		switch {
		case recordType == DNSTypeA && dataLength == 4:
			answer.IP = netip.AddrFrom4([4]byte(payload[dataStart : dataStart+4]))
		case recordType == DNSTypeAAAA && dataLength == 16:
			answer.IP = netip.AddrFrom16([16]byte(payload[dataStart : dataStart+16]))
		}
		message.Answers = append(message.Answers, answer)
		offset = dataStart + dataLength
	}
	return message, nil
}

// readDNSName decodes a (possibly compressed) DNS name starting at offset and
// returns the name plus the offset immediately after the name in the record it
// was read from.
func readDNSName(message []byte, offset int) (string, int, error) {
	if offset >= len(message) {
		return "", 0, ErrMalformedDNS
	}
	var labels []string
	length := 0
	cursor := offset
	resume := -1
	for jumps := 0; ; jumps++ {
		if jumps > dnsMaxJumps || cursor >= len(message) {
			return "", 0, ErrMalformedDNS
		}
		octet := int(message[cursor])
		switch {
		case octet == 0:
			cursor++
			if resume == -1 {
				resume = cursor
			}
			return normalizeDNSName(labels, length), resume, nil
		case octet&0xc0 == 0xc0:
			if cursor+1 >= len(message) {
				return "", 0, ErrMalformedDNS
			}
			pointer := int(binary.BigEndian.Uint16(message[cursor:cursor+2]) & 0x3fff)
			if pointer >= len(message) || pointer == cursor {
				return "", 0, ErrMalformedDNS
			}
			if resume == -1 {
				resume = cursor + 2
			}
			cursor = pointer
		case octet&0xc0 != 0:
			return "", 0, ErrMalformedDNS
		default:
			cursor++
			if cursor+octet > len(message) {
				return "", 0, ErrMalformedDNS
			}
			length += octet + 1
			if length > dnsMaxNameLen {
				return "", 0, ErrMalformedDNS
			}
			labels = append(labels, string(message[cursor:cursor+octet]))
			cursor += octet
		}
	}
}

func normalizeDNSName(labels []string, _ int) string {
	if len(labels) == 0 {
		return "."
	}
	return strings.ToLower(strings.Join(labels, "."))
}
