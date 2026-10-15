package packet

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

func TestParseDNSQuery(t *testing.T) {
	message, err := ParseDNS(dnsQuery("www.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if message.Response || len(message.Questions) != 1 {
		t.Fatalf("unexpected message: %#v", message)
	}
	if message.Questions[0].Name != "www.example.com" || message.Questions[0].Type != DNSTypeA {
		t.Fatalf("unexpected question: %#v", message.Questions[0])
	}
}

func TestParseDNSResponseWithCompressedName(t *testing.T) {
	query := dnsQuery("cdn.example.com")
	response := dnsResponse(query, netip.MustParseAddr("203.0.113.10"))

	message, err := ParseDNS(response)
	if err != nil {
		t.Fatal(err)
	}
	if !message.Response || len(message.Answers) != 1 {
		t.Fatalf("unexpected message: %#v", message)
	}
	answer := message.Answers[0]
	if answer.Name != "cdn.example.com" || answer.IP != netip.MustParseAddr("203.0.113.10") || answer.Type != DNSTypeA {
		t.Fatalf("unexpected answer: %#v", answer)
	}
}

func TestParseDNSAAAAAnswer(t *testing.T) {
	query := dnsQuery("v6.example.com")
	response := dnsAAAAAResponse(query, netip.MustParseAddr("2001:db8::1"))

	message, err := ParseDNS(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(message.Answers) != 1 || message.Answers[0].IP != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("unexpected answer: %#v", message.Answers)
	}
}

func TestParseDNSRejectsMalformed(t *testing.T) {
	valid := dnsQuery("example.com")
	loop := make([]byte, 12)
	loop[0], loop[1] = 0x12, 0x34
	binary.BigEndian.PutUint16(loop[4:6], 1)
	loop = append(loop, 0xc0, 0x0c) // pointer to itself, no question data

	truncatedName := append([]byte(nil), valid...)
	truncatedName = truncatedName[:len(truncatedName)-4]

	for name, payload := range map[string][]byte{
		"short header":      {1, 2, 3},
		"compression loop":  loop,
		"truncated name":    truncatedName,
		"reserved opcode":   {0, 1, 0x08, 0x00, 0, 1, 0, 0, 0, 0, 0, 0},
		"label length over": append([]byte{0, 1, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}, 0x3f, 'a', 'b'),
	} {
		if _, err := ParseDNS(payload); err == nil {
			t.Fatalf("%s: accepted malformed DNS", name)
		}
	}
}

func dnsQuery(name string) []byte {
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[0:2], 0x1234)
	binary.BigEndian.PutUint16(message[2:4], 0x0100)
	binary.BigEndian.PutUint16(message[4:6], 1)
	message = append(message, encodeDNSName(name)...)
	message = append(message, 0x00, 0x01, 0x00, 0x01)
	return message
}

func dnsResponse(query []byte, address netip.Addr) []byte {
	message := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(message[2:4], 0x8180)
	binary.BigEndian.PutUint16(message[6:8], 1)
	message = append(message, 0xc0, 0x0c) // pointer to the question name at offset 12
	message = append(message, 0x00, 0x01, 0x00, 0x01)
	message = append(message, 0x00, 0x00, 0x00, 0x3c) // TTL 60
	message = append(message, 0x00, 0x04)
	message = append(message, address.AsSlice()...)
	return message
}

func dnsAAAAAResponse(query []byte, address netip.Addr) []byte {
	message := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(message[2:4], 0x8180)
	binary.BigEndian.PutUint16(message[6:8], 1)
	message = append(message, 0xc0, 0x0c)
	message = append(message, 0x00, 0x1c, 0x00, 0x01)
	message = append(message, 0x00, 0x00, 0x00, 0x3c)
	message = append(message, 0x00, 0x10)
	message = append(message, address.AsSlice()...)
	return message
}

func encodeDNSName(name string) []byte {
	var encoded []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, label...)
	}
	return append(encoded, 0)
}
