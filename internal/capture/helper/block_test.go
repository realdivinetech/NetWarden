package helper

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

func newBlockSession(t *testing.T) *bandwidthSession {
	t.Helper()
	local := mustHelperMAC(t, "02:00:00:00:00:10")
	prefix := netip.MustParsePrefix("192.168.1.10/24")
	recorder := &bandwidthRecorder{sent: make(chan []byte, 4)}
	session, err := newBandwidthSession(context.Background(), local,
		netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("192.168.1.1"), prefix, recorder.send)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.close() })
	session.onLink = func(address netip.Addr) bool { return prefix.Contains(address.Unmap()) }
	return session
}

func TestBlockDropsBlockedDomainAndLearnsPeerAddress(t *testing.T) {
	session := newBlockSession(t)
	device := mustHelperMAC(t, "02:00:00:00:00:20")
	server := mustHelperMAC(t, "02:00:00:00:00:0b")
	gateway := mustHelperMAC(t, "02:00:00:00:00:01")
	deviceIP := netip.MustParseAddr("192.168.1.20")
	serverIP := netip.MustParseAddr("198.51.100.9")
	blockedIP := netip.MustParseAddr("203.0.113.5")

	if err := session.setBlock([]netip.Addr{deviceIP}, device, []string{"Blocked.Example.COM."}); err != nil {
		t.Fatalf("valid block rejected: %v", err)
	}

	answer := dnsAddressResponse("blocked.example.com", blockedIP)
	fromServer := ethernetIPv4(device, server, serverIP, deviceIP, 17, udpSegment(53, 51000, answer))
	if !session.dropBlocked(fromServer) {
		t.Fatal("blocked domain answer was not dropped")
	}

	direct := helperIPv4Frame(gateway, device, deviceIP, blockedIP)
	if !session.dropBlocked(direct) {
		t.Fatal("learned peer address was not blocked")
	}

	safe := ethernetIPv4(device, server, serverIP, deviceIP, 17, udpSegment(53, 51000,
		dnsAddressResponse("safe.example.com", netip.MustParseAddr("203.0.113.6"))))
	if session.dropBlocked(safe) {
		t.Fatal("unrelated domain was dropped")
	}
	other := helperIPv4Frame(gateway, device, deviceIP, netip.MustParseAddr("1.1.1.1"))
	if session.dropBlocked(other) {
		t.Fatal("unrelated flow was dropped")
	}

	if err := session.removeBlock(device); err != nil {
		t.Fatal(err)
	}
	if session.dropBlocked(fromServer) {
		t.Fatal("blocked domain kept dropping after removal")
	}
}

func TestBlockRejectsUnsafeTargets(t *testing.T) {
	session := newBlockSession(t)
	device := mustHelperMAC(t, "02:00:00:00:00:20")
	local := mustHelperMAC(t, "02:00:00:00:00:10")
	gateway := mustHelperMAC(t, "02:00:00:00:00:01")
	session.observeGateway(gateway)
	deviceIP := netip.MustParseAddr("192.168.1.20")

	cases := []struct {
		name      string
		addresses []netip.Addr
		mac       net.HardwareAddr
		domains   []string
	}{
		{"gateway mac", []netip.Addr{deviceIP}, gateway, []string{"example.com"}},
		{"local mac", []netip.Addr{deviceIP}, local, []string{"example.com"}},
		{"off-link address", []netip.Addr{netip.MustParseAddr("10.0.0.5")}, device, []string{"example.com"}},
		{"gateway address", []netip.Addr{netip.MustParseAddr("192.168.1.1")}, device, []string{"example.com"}},
		{"no domains", []netip.Addr{deviceIP}, device, []string{"   "}},
		{"no addresses", nil, device, []string{"example.com"}},
	}
	for _, test := range cases {
		if err := session.setBlock(test.addresses, test.mac, test.domains); err == nil {
			t.Fatalf("%s: unsafe block was accepted", test.name)
		}
		if session.dropBlocked(helperIPv4Frame(local, device, deviceIP, netip.MustParseAddr("1.1.1.1"))) {
			t.Fatalf("%s: rejected block still dropped traffic", test.name)
		}
	}
}

func TestBlockInactiveSessionNeverDrops(t *testing.T) {
	session := &bandwidthSession{}
	frame := helperIPv4Frame(net.HardwareAddr{0x02, 0, 0, 0, 0, 0x10}, net.HardwareAddr{0x02, 0, 0, 0, 0, 0x20},
		netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("198.51.100.1"))
	if session.dropBlocked(frame) {
		t.Fatal("session without block targets dropped a frame")
	}
}
