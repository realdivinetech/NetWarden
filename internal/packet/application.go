package packet

import (
	"net/netip"
	"strings"

	"github.com/amdzy/NetWarden/internal/platform"
)

// Kind identifies the protocol a domain observation was derived from.
type Kind uint8

const (
	KindDNS Kind = iota + 1
	KindSNI
)

func (k Kind) String() string {
	switch k {
	case KindDNS:
		return "dns"
	case KindSNI:
		return "sni"
	default:
		return "unknown"
	}
}

// Observation is a privacy-preserving Layer 7 attribution: a domain name bound
// to an on-link device address. Payload bytes are never retained.
type Observation struct {
	Kind     Kind       `json:"kind"`
	Domain   string     `json:"domain"`
	Platform string     `json:"platform,omitempty"`
	Device   netip.Addr `json:"device"`
	Remote   netip.Addr `json:"remote,omitempty"`
}

const maxDomainLength = 253

// InspectApplication passively extracts domain metadata from a captured frame.
// onLink reports whether an address belongs to the local network; it may be nil.
// Only DNS responses (which carry address bindings) and TLS ClientHello records
// with SNI are interpreted, and only the outer hostname is ever extracted.
func InspectApplication(frame []byte, onLink func(netip.Addr) bool) []Observation {
	transport, err := ParseTransport(frame)
	if err != nil {
		return nil
	}
	switch {
	case transport.Protocol == IPProtocolUDP && (transport.SourcePort == 53 || transport.DestinationPort == 53):
		return dnsObservations(transport, onLink)
	case transport.Protocol == IPProtocolTCP && transport.DestinationPort == 443:
		return sniObservations(transport, onLink)
	default:
		return nil
	}
}

func dnsObservations(transport Transport, onLink func(netip.Addr) bool) []Observation {
	message, err := ParseDNS(transport.Payload)
	if err != nil || !message.Response {
		return nil
	}
	device, _ := attribute(transport, onLink)
	if !device.IsValid() {
		return nil
	}
	var observations []Observation
	for _, answer := range message.Answers {
		domain := sanitizeDomain(answer.Name)
		if domain == "" || !answer.IP.IsValid() {
			continue
		}
		observations = append(observations, Observation{
			Kind:     KindDNS,
			Domain:   domain,
			Platform: platform.New().Classify(domain),
			Device:   device,
			Remote:   answer.IP,
		})
	}
	return observations
}

func sniObservations(transport Transport, onLink func(netip.Addr) bool) []Observation {
	name, err := ParseTLSClientHello(transport.Payload)
	if err != nil {
		return nil
	}
	domain := sanitizeDomain(name)
	if domain == "" {
		return nil
	}
	device, remote := attribute(transport, onLink)
	if !device.IsValid() {
		return nil
	}
	return []Observation{{Kind: KindSNI, Domain: domain, Platform: platform.New().Classify(domain), Device: device, Remote: remote}}
}

// attribute picks the on-link endpoint of a flow as the device and the other
// endpoint as the remote peer. When neither endpoint is on-link the flow cannot
// be attributed and is dropped.
func attribute(transport Transport, onLink func(netip.Addr) bool) (device, remote netip.Addr) {
	if onLink == nil {
		return netip.Addr{}, netip.Addr{}
	}
	source, destination := transport.SourceIP.Unmap(), transport.DestinationIP.Unmap()
	sourceOnLink, destinationOnLink := onLink(source), onLink(destination)
	switch {
	case sourceOnLink && !destinationOnLink:
		return source, destination
	case destinationOnLink && !sourceOnLink:
		return destination, source
	case sourceOnLink && destinationOnLink:
		return source, destination
	default:
		return netip.Addr{}, netip.Addr{}
	}
}

// sanitizeDomain accepts only conservative, printable ASCII hostnames so that
// untrusted DNS/SNI strings cannot reach the UI or logs unvalidated.
func sanitizeDomain(name string) string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" || len(name) > maxDomainLength {
		return ""
	}
	for _, symbol := range name {
		switch {
		case symbol >= 'a' && symbol <= 'z':
		case symbol >= '0' && symbol <= '9':
		case symbol == '.' || symbol == '-' || symbol == '_':
		default:
			return ""
		}
	}
	return name
}
