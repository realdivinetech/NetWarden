package helper

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"strings"

	"github.com/amdzy/NetWarden/internal/packet"
)

const (
	maxBlockedDomains      = 1024
	maxBlockedDomainLength = 253
)

// blockTarget is a per-device content filter enforced inside the privileged
// helper. Payload bytes are examined only long enough to derive a drop decision
// and learn the resolved peer addresses of blocked domains.
type blockTarget struct {
	mac     net.HardwareAddr
	devices []netip.Addr
	domains map[string]struct{}
	addrs   map[netip.Addr]struct{}
}

func (s *bandwidthSession) setBlock(addresses []netip.Addr, mac net.HardwareAddr, domains []string) error {
	addresses = normalizeTargetAddresses(addresses)
	if len(addresses) == 0 {
		return errors.New("block target requires at least one address")
	}
	if !validUnicastMAC(mac) || bytes.Equal(mac, s.localMAC) {
		return errors.New("block target requires a distinct unicast MAC")
	}
	for _, address := range addresses {
		if err := s.validBlockAddress(address); err != nil {
			return err
		}
	}
	cleaned := normalizeBlockedDomains(domains)
	if len(cleaned) == 0 {
		return errors.New("block target requires at least one domain")
	}
	s.mu.RLock()
	isGateway := bytes.Equal(mac, s.gatewayMAC)
	s.mu.RUnlock()
	if isGateway {
		return errors.New("the default gateway cannot be blocked")
	}
	lookup := make(map[string]struct{}, len(cleaned))
	for _, domain := range cleaned {
		lookup[domain] = struct{}{}
	}
	key := mac.String()
	s.mu.Lock()
	target := s.blocked[key]
	if target == nil {
		target = &blockTarget{mac: append(net.HardwareAddr(nil), mac...), addrs: make(map[netip.Addr]struct{})}
		s.blocked[key] = target
	}
	target.devices = append([]netip.Addr(nil), addresses...)
	target.domains = lookup
	s.mu.Unlock()
	return nil
}

func (s *bandwidthSession) removeBlock(mac net.HardwareAddr) error {
	s.mu.Lock()
	delete(s.blocked, mac.String())
	s.mu.Unlock()
	return nil
}

// dropBlocked reports whether a frame belongs to a blocked device and should be
// discarded. A DNS answer or TLS ClientHello naming a blocked domain is dropped
// and its peer address is remembered so subsequent direct flows are blocked too.
func (s *bandwidthSession) dropBlocked(frame []byte) bool {
	s.mu.RLock()
	active := len(s.blocked) > 0
	s.mu.RUnlock()
	if !active {
		return false
	}
	source, destination, ok := frameAddresses(frame)
	if !ok {
		return false
	}
	s.mu.RLock()
	var target *blockTarget
	for _, candidate := range s.blocked {
		if containsAddress(candidate.devices, source) || containsAddress(candidate.devices, destination) {
			target = candidate
			break
		}
	}
	s.mu.RUnlock()
	if target == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blocked[target.mac.String()] != target {
		return false
	}
	if _, blocked := target.addrs[source]; blocked {
		return true
	}
	if _, blocked := target.addrs[destination]; blocked {
		return true
	}
	for _, observation := range packet.InspectApplication(frame, s.onLink) {
		if _, blocked := target.domains[observation.Domain]; !blocked {
			continue
		}
		if observation.Remote.IsValid() {
			target.addrs[observation.Remote.Unmap()] = struct{}{}
		}
		return true
	}
	return false
}

func (s *bandwidthSession) validBlockAddress(address netip.Addr) error {
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
		return errors.New("block target requires unicast on-link addresses")
	}
	if address == s.localIP || address == s.gatewayIP {
		return errors.New("block target cannot be the local interface or gateway")
	}
	if !s.onLink(address) {
		return errors.New("block target is outside the local network")
	}
	return nil
}

func containsAddress(addresses []netip.Addr, address netip.Addr) bool {
	for _, candidate := range addresses {
		if candidate == address {
			return true
		}
	}
	return false
}

func normalizeBlockedDomains(domains []string) []string {
	seen := make(map[string]struct{}, len(domains))
	result := make([]string, 0, len(domains))
	for _, domain := range domains {
		if len(result) >= maxBlockedDomains {
			break
		}
		cleaned, ok := sanitizeBlockedDomain(domain)
		if !ok {
			continue
		}
		if _, exists := seen[cleaned]; exists {
			continue
		}
		seen[cleaned] = struct{}{}
		result = append(result, cleaned)
	}
	return result
}

func sanitizeBlockedDomain(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" || len(value) > maxBlockedDomainLength || strings.Contains(value, "..") {
		return "", false
	}
	for _, symbol := range value {
		switch {
		case symbol >= 'a' && symbol <= 'z':
		case symbol >= '0' && symbol <= '9':
		case symbol == '.' || symbol == '-' || symbol == '_':
		default:
			return "", false
		}
	}
	return value, true
}
