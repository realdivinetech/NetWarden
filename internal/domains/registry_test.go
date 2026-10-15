package domains

import (
	"net/netip"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/packet"
)

var (
	deviceA = netip.MustParseAddr("10.0.0.10")
	deviceB = netip.MustParseAddr("10.0.0.11")
)

func TestRegistryObserveAndLookup(t *testing.T) {
	registry := NewRegistry(16, time.Hour)
	at := time.Unix(1000, 0).UTC()
	observations := []packet.Observation{
		{Kind: packet.KindDNS, Domain: "example.com", Device: deviceA, Remote: netip.MustParseAddr("203.0.113.1")},
	}

	changed := registry.Observe(observations, at)
	if len(changed) != 1 || changed[0] != deviceA {
		t.Fatalf("unexpected changed set: %#v", changed)
	}
	if registry.Len() != 1 {
		t.Fatalf("unexpected length: %d", registry.Len())
	}
	entries := registry.ForAddresses([]netip.Addr{deviceA}, at)
	if len(entries) != 1 || entries[0].Domain != "example.com" || entries[0].Kind != packet.KindDNS {
		t.Fatalf("unexpected entries: %#v", entries)
	}
	if !entries[0].FirstSeen.Equal(at) || !entries[0].LastSeen.Equal(at) {
		t.Fatalf("unexpected timestamps: %#v", entries[0])
	}
}

func TestRegistryObserveDeduplicates(t *testing.T) {
	registry := NewRegistry(16, time.Hour)
	start := time.Unix(1000, 0).UTC()
	registry.Observe([]packet.Observation{{Kind: packet.KindSNI, Domain: "example.com", Device: deviceA}}, start)

	later := start.Add(time.Minute)
	changed := registry.Observe([]packet.Observation{{Kind: packet.KindSNI, Domain: "example.com", Device: deviceA}}, later)
	if len(changed) != 0 {
		t.Fatalf("repeat observation should not report change: %#v", changed)
	}
	if registry.Len() != 1 {
		t.Fatalf("unexpected length: %d", registry.Len())
	}
	if entries := registry.ForAddresses([]netip.Addr{deviceA}, later); !entries[0].LastSeen.Equal(later) {
		t.Fatalf("last seen not refreshed: %#v", entries[0])
	}
}

func TestRegistryExpiresEntries(t *testing.T) {
	registry := NewRegistry(16, time.Minute)
	start := time.Unix(1000, 0).UTC()
	registry.Observe([]packet.Observation{{Kind: packet.KindDNS, Domain: "example.com", Device: deviceA}}, start)

	if entries := registry.ForAddresses([]netip.Addr{deviceA}, start.Add(2*time.Minute)); len(entries) != 0 {
		t.Fatalf("expired entry returned: %#v", entries)
	}
	if changed := registry.Prune(start.Add(2 * time.Minute)); len(changed) != 1 {
		t.Fatalf("prune should report the device: %#v", changed)
	}
	if registry.Len() != 0 {
		t.Fatalf("prune did not clear entries: %d", registry.Len())
	}
}

func TestRegistryEnforcesLimit(t *testing.T) {
	registry := NewRegistry(2, time.Hour)
	start := time.Unix(1000, 0).UTC()
	for index, domain := range []string{"one.example", "two.example", "three.example"} {
		registry.Observe([]packet.Observation{{Kind: packet.KindDNS, Domain: domain, Device: deviceA}}, start.Add(time.Duration(index)*time.Second))
	}
	if registry.Len() != 2 {
		t.Fatalf("limit not enforced: %d", registry.Len())
	}
	entries := registry.ForAddresses([]netip.Addr{deviceA}, start.Add(time.Minute))
	names := map[string]bool{}
	for _, entry := range entries {
		names[entry.Domain] = true
	}
	if names["one.example"] {
		t.Fatalf("oldest entry should have been evicted: %#v", names)
	}
}

func TestRegistryMergesAcrossAddresses(t *testing.T) {
	registry := NewRegistry(16, time.Hour)
	at := time.Unix(1000, 0).UTC()
	v4 := netip.MustParseAddr("10.0.0.10")
	v4Mapped := netip.MustParseAddr("::ffff:10.0.0.10")
	registry.Observe([]packet.Observation{{Kind: packet.KindSNI, Domain: "example.com", Device: v4}}, at)

	entries := registry.ForAddresses([]netip.Addr{v4Mapped}, at)
	if len(entries) != 1 || entries[0].Domain != "example.com" {
		t.Fatalf("v4-mapped lookup failed: %#v", entries)
	}
}

func TestRegistrySeparatesDevices(t *testing.T) {
	registry := NewRegistry(16, time.Hour)
	at := time.Unix(1000, 0).UTC()
	registry.Observe([]packet.Observation{{Kind: packet.KindDNS, Domain: "a.example", Device: deviceA}}, at)
	registry.Observe([]packet.Observation{{Kind: packet.KindDNS, Domain: "b.example", Device: deviceB}}, at)

	if entries := registry.ForAddresses([]netip.Addr{deviceA}, at); len(entries) != 1 || entries[0].Domain != "a.example" {
		t.Fatalf("device A isolation failed: %#v", entries)
	}
	if entries := registry.ForAddresses([]netip.Addr{deviceB}, at); len(entries) != 1 || entries[0].Domain != "b.example" {
		t.Fatalf("device B isolation failed: %#v", entries)
	}
}
