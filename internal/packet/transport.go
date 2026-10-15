package packet

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

// EtherTypeIPv4 is defined here with the transport demultiplexer; EtherTypeIPv6
// lives with the IPv6/NDP parser.
const EtherTypeIPv4 = 0x0800

const (
	IPProtocolTCP = 6
	IPProtocolUDP = 17
)

const (
	etherTypeVLAN  = 0x8100
	etherTypeQinQ  = 0x88a8
	maxVLANDepth   = 2
	maxIPv6ExtHdrs = 8
)

var ErrMalformedTransport = errors.New("malformed Ethernet transport frame")

// Transport is the validated Layer 3/Layer 4 view of a captured frame. Payload
// points into the original frame buffer and is only valid while the caller's
// buffer is valid; callers that retain it must copy.
type Transport struct {
	SourceIP       netip.Addr
	DestinationIP  netip.Addr
	SourceMAC      net.HardwareAddr
	DestinationMAC net.HardwareAddr

	IPVersion uint8 // 4 or 6

	// Protocol is the Layer 4 protocol number (IPProtocolTCP, IPProtocolUDP, or
	// any other IP protocol). Ports are zero unless Protocol is TCP or UDP.
	Protocol        uint8
	SourcePort      uint16
	DestinationPort uint16

	// Payload is the Layer 4 payload (TCP segment data or UDP datagram body).
	Payload []byte
}

// ParseTransport decodes an Ethernet frame far enough to reach the TCP/UDP
// header, supporting IPv4, IPv6 (with a bounded extension-header walk), and up
// to two stacked VLAN tags. It never allocates beyond the header MAC slices and
// is safe for passive parsing of untrusted frames.
func ParseTransport(frame []byte) (Transport, error) {
	if len(frame) < EthernetHeaderLen {
		return Transport{}, ErrMalformedTransport
	}
	transport := Transport{
		SourceMAC:      append(net.HardwareAddr(nil), frame[6:12]...),
		DestinationMAC: append(net.HardwareAddr(nil), frame[0:6]...),
	}

	// l3 tracks the offset of the current EtherType field. Each VLAN tag adds a
	// 2-byte tag control field after the TPID, so the next EtherType is 4 bytes
	// further on.
	l3 := 12
	etherType := binary.BigEndian.Uint16(frame[12:14])
	for depth := 0; depth < maxVLANDepth && (etherType == etherTypeVLAN || etherType == etherTypeQinQ); depth++ {
		if l3+6 > len(frame) {
			return Transport{}, ErrMalformedTransport
		}
		etherType = binary.BigEndian.Uint16(frame[l3+4 : l3+6])
		l3 += 4
	}
	l3 += 2
	if l3 > len(frame) {
		return Transport{}, ErrMalformedTransport
	}

	payload := frame[l3:]
	switch etherType {
	case EtherTypeIPv4:
		var err error
		transport.IPVersion = 4
		transport.SourceIP, transport.DestinationIP, transport.Protocol, payload, err = parseIPv4(payload)
		if err != nil {
			return Transport{}, err
		}
	case EtherTypeIPv6:
		var err error
		transport.IPVersion = 6
		transport.SourceIP, transport.DestinationIP, transport.Protocol, payload, err = parseIPv6(payload)
		if err != nil {
			return Transport{}, err
		}
	default:
		return Transport{}, ErrMalformedTransport
	}

	switch transport.Protocol {
	case IPProtocolUDP:
		if len(payload) < 8 {
			return Transport{}, ErrMalformedTransport
		}
		transport.SourcePort = binary.BigEndian.Uint16(payload[0:2])
		transport.DestinationPort = binary.BigEndian.Uint16(payload[2:4])
		length := int(binary.BigEndian.Uint16(payload[4:6]))
		switch {
		case length == 0 || length > len(payload):
			transport.Payload = payload[8:]
		default:
			if length < 8 {
				return Transport{}, ErrMalformedTransport
			}
			transport.Payload = payload[8:length]
		}
	case IPProtocolTCP:
		if len(payload) < 20 {
			return Transport{}, ErrMalformedTransport
		}
		transport.SourcePort = binary.BigEndian.Uint16(payload[0:2])
		transport.DestinationPort = binary.BigEndian.Uint16(payload[2:4])
		dataOffset := int(payload[12]>>4) * 4
		if dataOffset < 20 || dataOffset > len(payload) {
			return Transport{}, ErrMalformedTransport
		}
		transport.Payload = payload[dataOffset:]
	}
	return transport, nil
}

func parseIPv4(frame []byte) (source, destination netip.Addr, protocol uint8, payload []byte, err error) {
	const headerLength = 20
	if len(frame) < headerLength || frame[0]>>4 != 4 {
		return netip.Addr{}, netip.Addr{}, 0, nil, ErrMalformedTransport
	}
	ihl := int(frame[0]&0x0f) * 4
	if ihl < headerLength || ihl > len(frame) {
		return netip.Addr{}, netip.Addr{}, 0, nil, ErrMalformedTransport
	}
	totalLength := int(binary.BigEndian.Uint16(frame[2:4]))
	if totalLength < ihl {
		return netip.Addr{}, netip.Addr{}, 0, nil, ErrMalformedTransport
	}
	if totalLength > len(frame) {
		totalLength = len(frame)
	}
	// A non-initial fragment carries no TCP/UDP header.
	if binary.BigEndian.Uint16(frame[6:8])&0x1fff != 0 {
		return netip.Addr{}, netip.Addr{}, 0, nil, ErrMalformedTransport
	}
	source = netip.AddrFrom4([4]byte(frame[12:16]))
	destination = netip.AddrFrom4([4]byte(frame[16:20]))
	return source, destination, frame[9], frame[ihl:totalLength], nil
}

func parseIPv6(frame []byte) (source, destination netip.Addr, nextHeader uint8, payload []byte, err error) {
	const headerLength = 40
	if len(frame) < headerLength || frame[0]>>4 != 6 {
		return netip.Addr{}, netip.Addr{}, 0, nil, ErrMalformedTransport
	}
	end := headerLength + int(binary.BigEndian.Uint16(frame[4:6]))
	if end > len(frame) {
		end = len(frame)
	}
	source = netip.AddrFrom16([16]byte(frame[8:24]))
	destination = netip.AddrFrom16([16]byte(frame[24:40]))
	nextHeader = frame[6]
	offset := headerLength

	resolved := false
	for hop := 0; hop < maxIPv6ExtHdrs; hop++ {
		switch nextHeader {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			length, ok := extensionLength(frame, offset, 8, 1)
			if !ok {
				return netip.Addr{}, netip.Addr{}, 0, nil, ErrMalformedTransport
			}
			nextHeader = frame[offset]
			offset += length
		case 44: // fragment
			if offset+8 > end {
				return netip.Addr{}, netip.Addr{}, 0, nil, ErrMalformedTransport
			}
			if binary.BigEndian.Uint16(frame[offset+2:offset+4])>>3 != 0 {
				return netip.Addr{}, netip.Addr{}, 0, nil, ErrMalformedTransport
			}
			nextHeader = frame[offset]
			offset += 8
		case 51: // authentication header
			length, ok := extensionLength(frame, offset, 4, 2)
			if !ok {
				return netip.Addr{}, netip.Addr{}, 0, nil, ErrMalformedTransport
			}
			nextHeader = frame[offset]
			offset += length
		default:
			resolved = true
		}
		if resolved {
			break
		}
		if offset > end {
			return netip.Addr{}, netip.Addr{}, 0, nil, ErrMalformedTransport
		}
	}
	if offset > end {
		return netip.Addr{}, netip.Addr{}, 0, nil, ErrMalformedTransport
	}
	return source, destination, nextHeader, frame[offset:end], nil
}

// extensionLength reads the length byte at offset+1 and scales it, guarding
// against zero-length headers and buffers that end before the header does.
func extensionLength(frame []byte, offset, unit, bias int) (int, bool) {
	if offset+2 > len(frame) {
		return 0, false
	}
	length := (int(frame[offset+1]) + bias) * unit
	if length <= 0 || offset+length > len(frame) {
		return 0, false
	}
	return length, true
}
