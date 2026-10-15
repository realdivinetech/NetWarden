package packet

import (
	"net"
	"net/netip"
	"testing"
)

func TestInspectApplicationDNSResponse(t *testing.T) {
	deviceMAC, _ := net.ParseMAC("02:00:00:00:00:0a")
	serverMAC, _ := net.ParseMAC("02:00:00:00:00:0b")
	device := netip.MustParseAddr("10.0.0.10")
	server := netip.MustParseAddr("8.8.8.8")
	answer := netip.MustParseAddr("203.0.113.10")
	response := dnsResponse(dnsQuery("cdn.example.com"), answer)
	frame := ethernetFrame(deviceMAC, serverMAC, EtherTypeIPv4, ipv4Frame(server, device, IPProtocolUDP, udpSegment(53, 51000, response)))

	observations := InspectApplication(frame, prefixPredicate("10.0.0.0/24"))
	if len(observations) != 1 {
		t.Fatalf("expected 1 observation, got %#v", observations)
	}
	got := observations[0]
	if got.Kind != KindDNS || got.Domain != "cdn.example.com" || got.Device != device || got.Remote != answer {
		t.Fatalf("unexpected observation: %#v", got)
	}
}

func TestInspectApplicationTLSClientHello(t *testing.T) {
	deviceMAC, _ := net.ParseMAC("02:00:00:00:00:0a")
	serverMAC, _ := net.ParseMAC("02:00:00:00:00:0b")
	device := netip.MustParseAddr("10.0.0.10")
	server := netip.MustParseAddr("93.184.216.34")
	frame := ethernetFrame(serverMAC, deviceMAC, EtherTypeIPv4, ipv4Frame(device, server, IPProtocolTCP, tcpSegment(40000, 443, tlsClientHello("Secure.Example.COM"))))

	observations := InspectApplication(frame, prefixPredicate("10.0.0.0/24"))
	if len(observations) != 1 {
		t.Fatalf("expected 1 observation, got %#v", observations)
	}
	got := observations[0]
	if got.Kind != KindSNI || got.Domain != "secure.example.com" || got.Device != device || got.Remote != server {
		t.Fatalf("unexpected observation: %#v", got)
	}
}

func TestInspectApplicationIgnoresQueriesAndUnattributableFlows(t *testing.T) {
	deviceMAC, _ := net.ParseMAC("02:00:00:00:00:0a")
	serverMAC, _ := net.ParseMAC("02:00:00:00:00:0b")
	device := netip.MustParseAddr("10.0.0.10")
	server := netip.MustParseAddr("8.8.8.8")

	query := ethernetFrame(serverMAC, deviceMAC, EtherTypeIPv4, ipv4Frame(device, server, IPProtocolUDP, udpSegment(51000, 53, dnsQuery("example.com"))))
	if got := InspectApplication(query, prefixPredicate("10.0.0.0/24")); len(got) != 0 {
		t.Fatalf("query should not be attributed: %#v", got)
	}

	offLink := ethernetFrame(serverMAC, deviceMAC, EtherTypeIPv4, ipv4Frame(netip.MustParseAddr("192.168.1.5"), server, IPProtocolUDP, udpSegment(53, 51000, dnsResponse(dnsQuery("x.example.com"), netip.MustParseAddr("203.0.113.1")))))
	if got := InspectApplication(offLink, prefixPredicate("10.0.0.0/24")); len(got) != 0 {
		t.Fatalf("off-link flow should not be attributed: %#v", got)
	}

	if got := InspectApplication(query, nil); len(got) != 0 {
		t.Fatalf("nil on-link predicate should attribute nothing: %#v", got)
	}
}

func TestInspectApplicationRejectsUntrustedDomain(t *testing.T) {
	deviceMAC, _ := net.ParseMAC("02:00:00:00:00:0a")
	serverMAC, _ := net.ParseMAC("02:00:00:00:00:0b")
	device := netip.MustParseAddr("10.0.0.10")
	server := netip.MustParseAddr("8.8.8.8")
	response := dnsResponse(dnsQuery("evil.com;rm"), netip.MustParseAddr("203.0.113.9"))
	frame := ethernetFrame(deviceMAC, serverMAC, EtherTypeIPv4, ipv4Frame(server, device, IPProtocolUDP, udpSegment(53, 51000, response)))

	if got := InspectApplication(frame, prefixPredicate("10.0.0.0/24")); len(got) != 0 {
		t.Fatalf("untrusted domain should be dropped: %#v", got)
	}
}

func TestSanitizeDomain(t *testing.T) {
	for input, want := range map[string]string{
		"Example.COM.":  "example.com",
		"a-b_c.example": "a-b_c.example",
		"":              "",
		"bad domain":    "",
		"héllo.com":     "",
		"x;y":           "",
	} {
		if got := sanitizeDomain(input); got != want {
			t.Fatalf("sanitizeDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

func prefixPredicate(cidr string) func(netip.Addr) bool {
	prefix := netip.MustParsePrefix(cidr)
	return func(address netip.Addr) bool { return prefix.Contains(address.Unmap()) }
}
