package helper

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/packet"
)

type borrowedProtocolDriver struct {
	borrowed atomic.Bool
	regular  atomic.Bool
}

func (d *borrowedProtocolDriver) Run(ctx context.Context, _ func(capture.Frame) error) error {
	d.regular.Store(true)
	<-ctx.Done()
	return ctx.Err()
}

func (d *borrowedProtocolDriver) RunBorrowed(ctx context.Context, _ func(capture.Frame) error) error {
	d.borrowed.Store(true)
	<-ctx.Done()
	return ctx.Err()
}

func (*borrowedProtocolDriver) Send(context.Context, []byte) error { return nil }
func (*borrowedProtocolDriver) Close() error                       { return nil }

func TestServeUsesBorrowedFrameDriverWhenAvailable(t *testing.T) {
	driver := &borrowedProtocolDriver{}
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	err := Serve(context.Background(), driver, localMAC,
		netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("192.168.1.1"),
		netip.MustParsePrefix("192.168.1.10/24"), nil, bytes.NewReader(nil), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if !driver.borrowed.Load() || driver.regular.Load() {
		t.Fatalf("borrowed=%t regular=%t", driver.borrowed.Load(), driver.regular.Load())
	}
}

func TestValidateDiscoveryFrameRestrictsSenderAndOperation(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	targetMAC, _ := net.ParseMAC("00:00:00:00:00:00")
	localIP := netip.MustParseAddr("192.168.1.10")
	prefix := netip.MustParsePrefix("192.168.1.10/24")
	frame, err := packet.MarshalARP(net.HardwareAddr{255, 255, 255, 255, 255, 255}, localMAC, packet.ARP{
		Operation: packet.ARPOpRequest, SenderMAC: localMAC, SenderIP: localIP,
		TargetMAC: targetMAC, TargetIP: netip.MustParseAddr("192.168.1.20"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateDiscoveryFrame(frame, localMAC, localIP, prefix); err != nil {
		t.Fatal(err)
	}
	frame[packet.EthernetHeaderLen+7] = byte(packet.ARPOpReply)
	if err := ValidateDiscoveryFrame(frame, localMAC, localIP, prefix); err == nil {
		t.Fatal("helper accepted an ARP reply")
	}
}

func TestValidateControlFrameAllowsOnlyScopedIsolationAndVerifiedRestoration(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	gatewayMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	targetMAC, _ := net.ParseMAC("02:00:00:00:00:20")
	localIP := netip.MustParseAddr("192.168.1.10")
	gatewayIP := netip.MustParseAddr("192.168.1.1")
	targetIP := netip.MustParseAddr("192.168.1.20")
	prefix := netip.MustParsePrefix("192.168.1.10/24")
	makeFrame := func(sender net.HardwareAddr) []byte {
		frame, err := packet.MarshalARP(targetMAC, sender, packet.ARP{
			Operation: packet.ARPOpReply, SenderMAC: sender, SenderIP: gatewayIP,
			TargetMAC: targetMAC, TargetIP: targetIP,
		})
		if err != nil {
			t.Fatal(err)
		}
		return frame
	}
	if err := ValidateControlFrame(makeFrame(localMAC), localMAC, gatewayMAC, localIP, gatewayIP, prefix); err != nil {
		t.Fatalf("isolation rejected: %v", err)
	}
	if err := ValidateControlFrame(makeFrame(gatewayMAC), localMAC, gatewayMAC, localIP, gatewayIP, prefix); err != nil {
		t.Fatalf("restoration rejected: %v", err)
	}
	unknownMAC, _ := net.ParseMAC("02:00:00:00:00:99")
	if err := ValidateControlFrame(makeFrame(unknownMAC), localMAC, gatewayMAC, localIP, gatewayIP, prefix); err == nil {
		t.Fatal("accepted an unverified control sender")
	}
}

func TestValidateIPv6DiscoveryFrameAllowsOnlyScopedSolicitations(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	localIP := netip.MustParseAddr("fe80::10")
	prefixes := []netip.Prefix{netip.MustParsePrefix("fe80::10/64"), netip.MustParsePrefix("2001:db8:1::10/64")}
	makeFrame := func(target netip.Addr) []byte {
		frame, err := packet.MarshalNeighborSolicitation(packet.NeighborSolicitation{SourceIP: localIP, SourceMAC: localMAC, TargetIP: target})
		if err != nil {
			t.Fatal(err)
		}
		return frame
	}
	valid := makeFrame(netip.MustParseAddr("2001:db8:1::20"))
	if err := ValidateIPv6DiscoveryFrame(valid, localMAC, prefixes); err != nil {
		t.Fatal(err)
	}
	if err := ValidateIPv6DiscoveryFrame(makeFrame(netip.MustParseAddr("2001:db8:2::20")), localMAC, prefixes); err == nil {
		t.Fatal("accepted an off-link target")
	}
	valid[0] ^= 1
	if err := ValidateIPv6DiscoveryFrame(valid, localMAC, prefixes); err == nil {
		t.Fatal("accepted the wrong multicast MAC")
	}
	nonCanonical := append(makeFrame(netip.MustParseAddr("2001:db8:1::20")), 0)
	if err := ValidateIPv6DiscoveryFrame(nonCanonical, localMAC, prefixes); err == nil {
		t.Fatal("accepted a non-canonical solicitation")
	}
}

// scriptedDriver feeds a fixed frame list to the protocol consumer and then
// waits for cancellation, so a test can observe exactly what Serve writes.
type scriptedDriver struct {
	frames []capture.Frame
}

func (d *scriptedDriver) Run(ctx context.Context, consume func(capture.Frame) error) error {
	for _, frame := range d.frames {
		if err := consume(frame); err != nil {
			return err
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

func (d *scriptedDriver) Send(context.Context, []byte) error { return nil }
func (d *scriptedDriver) Close() error                       { return nil }

func TestServeEmitsDomainMetadataWithoutPayloads(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	serverMAC, _ := net.ParseMAC("02:00:00:00:00:0b")
	localIP := netip.MustParseAddr("192.168.1.10")
	gatewayIP := netip.MustParseAddr("192.168.1.1")
	prefix := netip.MustParsePrefix("192.168.1.10/24")

	response := dnsAddressResponse("cdn.example.com", netip.MustParseAddr("203.0.113.10"))
	driver := &scriptedDriver{frames: []capture.Frame{{
		Data: ethernetIPv4(serverMAC, localMAC, netip.MustParseAddr("8.8.8.8"), localIP, 17, udpSegment(53, 51000, response)),
	}}}

	var found bool
	for _, message := range runServeAndCollect(t, driver, localMAC, localIP, gatewayIP, prefix) {
		if message.Type != "domains" {
			continue
		}
		found = true
		if len(message.Data) != 0 {
			t.Fatalf("domains message carried a payload: %d bytes", len(message.Data))
		}
		if len(message.Observations) != 1 {
			t.Fatalf("unexpected observations: %#v", message.Observations)
		}
		got := message.Observations[0]
		if got.Domain != "cdn.example.com" || got.Device != localIP || got.Remote != netip.MustParseAddr("203.0.113.10") {
			t.Fatalf("unexpected observation: %#v", got)
		}
	}
	if !found {
		t.Fatal("no domains message was emitted for a consumed DNS response")
	}
}

func TestServeDoesNotAttributeQueriesOrUnattributableFlows(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	serverMAC, _ := net.ParseMAC("02:00:00:00:00:0b")
	localIP := netip.MustParseAddr("192.168.1.10")
	gatewayIP := netip.MustParseAddr("192.168.1.1")
	prefix := netip.MustParsePrefix("192.168.1.10/24")

	query := dnsQueryPayload("example.com")
	response := dnsAddressResponse("x.example.com", netip.MustParseAddr("203.0.113.1"))
	driver := &scriptedDriver{frames: []capture.Frame{
		{Data: ethernetIPv4(localMAC, serverMAC, localIP, netip.MustParseAddr("8.8.8.8"), 17, udpSegment(51000, 53, query))},
		{Data: ethernetIPv4(serverMAC, localMAC, netip.MustParseAddr("198.51.100.5"), netip.MustParseAddr("198.51.100.6"), 17, udpSegment(53, 51000, response))},
	}}

	for _, message := range runServeAndCollect(t, driver, localMAC, localIP, gatewayIP, prefix) {
		if message.Type == "domains" {
			t.Fatalf("attributed a flow that should not be attributable: %#v", message.Observations)
		}
	}
}

func runServeAndCollect(t *testing.T, driver capture.Driver, localMAC net.HardwareAddr, localIP, gatewayIP netip.Addr, prefix netip.Prefix) []Message {
	t.Helper()
	reader, writer := io.Pipe()
	output := &syncBuffer{}
	_ = writer.Close()
	_ = Serve(context.Background(), driver, localMAC, localIP, gatewayIP, prefix, nil, reader, output)
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	var messages []Message
	for {
		var message Message
		if err := decoder.Decode(&message); err != nil {
			break
		}
		messages = append(messages, message)
	}
	return messages
}

// syncBuffer makes the encoder's writes safe to read after Serve returns.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.b.Bytes()...)
}

func ethernetIPv4(destination, source net.HardwareAddr, sourceIP, destinationIP netip.Addr, protocol uint8, payload []byte) []byte {
	frame := make([]byte, packet.EthernetHeaderLen+20+len(payload))
	copy(frame[0:6], destination)
	copy(frame[6:12], source)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	header := frame[packet.EthernetHeaderLen:]
	header[0] = 0x45
	binary.BigEndian.PutUint16(header[2:4], uint16(20+len(payload)))
	header[8] = 64
	header[9] = protocol
	source4, destination4 := sourceIP.As4(), destinationIP.As4()
	copy(header[12:16], source4[:])
	copy(header[16:20], destination4[:])
	copy(header[20:], payload)
	return frame
}

func udpSegment(sourcePort, destinationPort uint16, payload []byte) []byte {
	segment := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(segment[0:2], sourcePort)
	binary.BigEndian.PutUint16(segment[2:4], destinationPort)
	binary.BigEndian.PutUint16(segment[4:6], uint16(8+len(payload)))
	copy(segment[8:], payload)
	return segment
}

func dnsQueryPayload(name string) []byte {
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[0:2], 0x1234)
	binary.BigEndian.PutUint16(message[2:4], 0x0100)
	binary.BigEndian.PutUint16(message[4:6], 1)
	message = append(message, encodeDNSName(name)...)
	return append(message, 0x00, 0x01, 0x00, 0x01)
}

func dnsAddressResponse(name string, address netip.Addr) []byte {
	message := append([]byte(nil), dnsQueryPayload(name)...)
	binary.BigEndian.PutUint16(message[2:4], 0x8180)
	binary.BigEndian.PutUint16(message[6:8], 1)
	message = append(message, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01)
	message = append(message, 0x00, 0x00, 0x00, 0x3c)
	message = append(message, 0x00, 0x04)
	return append(message, address.AsSlice()...)
}

func encodeDNSName(name string) []byte {
	var encoded []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, label...)
	}
	return append(encoded, 0)
}
