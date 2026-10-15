package packet

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

func TestParseTransportIPv4UDP(t *testing.T) {
	sourceMAC, _ := net.ParseMAC("02:00:00:00:00:0a")
	destinationMAC, _ := net.ParseMAC("02:00:00:00:00:0b")
	source := netip.MustParseAddr("10.0.0.10")
	destination := netip.MustParseAddr("8.8.8.8")
	dns := dnsQuery("example.com")
	frame := ethernetFrame(destinationMAC, sourceMAC, EtherTypeIPv4, ipv4Frame(source, destination, IPProtocolUDP, udpSegment(51000, 53, dns)))

	transport, err := ParseTransport(frame)
	if err != nil {
		t.Fatal(err)
	}
	if transport.IPVersion != 4 || transport.Protocol != IPProtocolUDP {
		t.Fatalf("unexpected protocol: %#v", transport)
	}
	if transport.SourceIP != source || transport.DestinationIP != destination {
		t.Fatalf("unexpected addresses: %s -> %s", transport.SourceIP, transport.DestinationIP)
	}
	if transport.SourcePort != 51000 || transport.DestinationPort != 53 {
		t.Fatalf("unexpected ports: %d -> %d", transport.SourcePort, transport.DestinationPort)
	}
	if string(transport.Payload) != string(dns) {
		t.Fatalf("payload mismatch: %x", transport.Payload)
	}
	if transport.SourceMAC.String() != sourceMAC.String() || transport.DestinationMAC.String() != destinationMAC.String() {
		t.Fatalf("unexpected MACs: %s / %s", transport.SourceMAC, transport.DestinationMAC)
	}
}

func TestParseTransportIPv6TCPWithHopByHop(t *testing.T) {
	sourceMAC, _ := net.ParseMAC("02:00:00:00:00:0a")
	destinationMAC, _ := net.ParseMAC("02:00:00:00:00:0b")
	source := netip.MustParseAddr("2001:db8::10")
	destination := netip.MustParseAddr("2001:db8::20")
	tls := tlsClientHello("secure.example.com")

	hopByHop := []byte{IPProtocolTCP, 0, 0, 0, 0, 0, 0, 0} // next header TCP, length 8
	frame := ethernetFrame(destinationMAC, sourceMAC, EtherTypeIPv6, ipv6Frame(source, destination, 0, append(hopByHop, tcpSegment(40000, 443, tls)...)))

	transport, err := ParseTransport(frame)
	if err != nil {
		t.Fatal(err)
	}
	if transport.IPVersion != 6 || transport.Protocol != IPProtocolTCP || transport.DestinationPort != 443 {
		t.Fatalf("unexpected transport: %#v", transport)
	}
	if string(transport.Payload) != string(tls) {
		t.Fatalf("payload mismatch: %x", transport.Payload)
	}
}

func TestParseTransportStripsTwoVLANTags(t *testing.T) {
	sourceMAC, _ := net.ParseMAC("02:00:00:00:00:0a")
	destinationMAC, _ := net.ParseMAC("02:00:00:00:00:0b")
	source := netip.MustParseAddr("10.0.0.10")
	destination := netip.MustParseAddr("1.1.1.1")
	inner := ipv4Frame(source, destination, IPProtocolUDP, udpSegment(40000, 53, dnsQuery("vlan.test")))

	tagged := make([]byte, 0, len(inner)+8)
	tagged = append(tagged, 0x00, 0x64)             // first tag control field
	tagged = append(tagged, 0x81, 0x00, 0x00, 0xc8) // second TPID + control field
	tagged = append(tagged, 0x08, 0x00)             // inner EtherType
	tagged = append(tagged, inner...)
	frame := ethernetFrame(destinationMAC, sourceMAC, 0x8100, tagged)

	transport, err := ParseTransport(frame)
	if err != nil {
		t.Fatal(err)
	}
	if transport.DestinationPort != 53 || string(transport.Payload) != string(dnsQuery("vlan.test")) {
		t.Fatalf("unexpected transport: %#v", transport)
	}
}

func TestParseTransportRejectsMalformed(t *testing.T) {
	sourceMAC, _ := net.ParseMAC("02:00:00:00:00:0a")
	destinationMAC, _ := net.ParseMAC("02:00:00:00:00:0b")
	source := netip.MustParseAddr("10.0.0.10")
	destination := netip.MustParseAddr("8.8.8.8")

	valid := ethernetFrame(destinationMAC, sourceMAC, EtherTypeIPv4, ipv4Frame(source, destination, IPProtocolUDP, udpSegment(51000, 53, dnsQuery("example.com"))))

	for name, frame := range map[string][]byte{
		"empty":                 {},
		"truncated ethernet":    valid[:10],
		"truncated udp":         ethernetFrame(destinationMAC, sourceMAC, EtherTypeIPv4, ipv4Frame(source, destination, IPProtocolUDP, []byte{0, 1, 0, 2})),
		"bad ip version":        ethernetFrame(destinationMAC, sourceMAC, EtherTypeIPv4, append([]byte{0x35}, valid[EthernetHeaderLen+1:]...)),
		"non-initial fragment":  ethernetFrame(destinationMAC, sourceMAC, EtherTypeIPv4, ipv4Fragment(source, destination)),
		"unsupported ethertype": ethernetFrame(destinationMAC, sourceMAC, 0x0806, valid[EthernetHeaderLen:]),
	} {
		if _, err := ParseTransport(frame); err == nil {
			t.Fatalf("%s: accepted malformed frame", name)
		}
	}
}

func ethernetFrame(destination, source net.HardwareAddr, etherType uint16, payload []byte) []byte {
	frame := make([]byte, EthernetHeaderLen+len(payload))
	copy(frame[0:6], destination)
	copy(frame[6:12], source)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[EthernetHeaderLen:], payload)
	return frame
}

func ipv4Frame(source, destination netip.Addr, protocol uint8, payload []byte) []byte {
	header := make([]byte, 20)
	header[0] = 0x45
	binary.BigEndian.PutUint16(header[2:4], uint16(20+len(payload)))
	header[8] = 64
	header[9] = protocol
	copy(header[12:16], source.AsSlice())
	copy(header[16:20], destination.AsSlice())
	return append(header, payload...)
}

func ipv4Fragment(source, destination netip.Addr) []byte {
	header := make([]byte, 20)
	header[0] = 0x45
	binary.BigEndian.PutUint16(header[2:4], uint16(20+8))
	header[8] = 64
	header[9] = IPProtocolUDP
	binary.BigEndian.PutUint16(header[6:8], 0x0008) // fragment offset 1
	copy(header[12:16], source.AsSlice())
	copy(header[16:20], destination.AsSlice())
	return append(header, make([]byte, 8)...)
}

func ipv6Frame(source, destination netip.Addr, nextHeader uint8, payload []byte) []byte {
	header := make([]byte, 40)
	header[0] = 0x60
	binary.BigEndian.PutUint16(header[4:6], uint16(len(payload)))
	header[6] = nextHeader
	header[7] = 64
	copy(header[8:24], source.AsSlice())
	copy(header[24:40], destination.AsSlice())
	return append(header, payload...)
}

func udpSegment(sourcePort, destinationPort uint16, payload []byte) []byte {
	segment := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(segment[0:2], sourcePort)
	binary.BigEndian.PutUint16(segment[2:4], destinationPort)
	binary.BigEndian.PutUint16(segment[4:6], uint16(8+len(payload)))
	copy(segment[8:], payload)
	return segment
}

func tcpSegment(sourcePort, destinationPort uint16, payload []byte) []byte {
	segment := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(segment[0:2], sourcePort)
	binary.BigEndian.PutUint16(segment[2:4], destinationPort)
	segment[12] = 0x50
	segment[13] = 0x18
	binary.BigEndian.PutUint16(segment[14:16], 65535)
	copy(segment[20:], payload)
	return segment
}
