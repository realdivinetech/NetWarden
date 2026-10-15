// Package domains keeps a bounded, expiring record of the domain names observed
// for each on-link device address. It stores metadata only and never payloads.
package domains

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/amdzy/NetWarden/internal/packet"
)

const (
	DefaultMaxEntries = 4096
	DefaultTTL        = 10 * time.Minute
)

// Entry is a single domain attributed to a device.
type Entry struct {
	Domain    string      `json:"domain"`
	Kind      packet.Kind `json:"kind"`
	Platform  string      `json:"platform,omitempty"`
	Remote    netip.Addr  `json:"remote,omitempty"`
	FirstSeen time.Time   `json:"firstSeen"`
	LastSeen  time.Time   `json:"lastSeen"`
}

// Registry maps device addresses to the domains seen talking to or from them.
// It is safe for concurrent use.
type Registry struct {
	mu    sync.Mutex
	byIP  map[netip.Addr]map[string]Entry
	count int
	max   int
	ttl   time.Duration
}

// NewRegistry builds a registry bounded to max entries that forgets domains
// idle for longer than ttl. Zero or negative values fall back to the defaults.
func NewRegistry(max int, ttl time.Duration) *Registry {
	if max <= 0 {
		max = DefaultMaxEntries
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Registry{byIP: make(map[netip.Addr]map[string]Entry), max: max, ttl: ttl}
}

// Observe records the given observations and returns the device addresses that
// gained at least one previously unseen domain, so callers can emit a change
// event without clinging to the payload.
func (r *Registry) Observe(observations []packet.Observation, at time.Time) []netip.Addr {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var changed []netip.Addr
	for _, observation := range observations {
		device := observation.Device.Unmap()
		if !device.IsValid() || observation.Domain == "" {
			continue
		}
		entries := r.byIP[device]
		if entries == nil {
			entries = make(map[string]Entry)
			r.byIP[device] = entries
		}
		if existing, found := entries[observation.Domain]; found {
			existing.LastSeen = at
			if observation.Remote.IsValid() {
				existing.Remote = observation.Remote
			}
			// Update platform if the new observation has one and existing doesn't
			if existing.Platform == "" && observation.Platform != "" {
				existing.Platform = observation.Platform
			}
			entries[observation.Domain] = existing
			continue
		}
		entries[observation.Domain] = Entry{
			Domain:    observation.Domain,
			Kind:      observation.Kind,
			Platform:  observation.Platform,
			Remote:    observation.Remote,
			FirstSeen: at,
			LastSeen:  at,
		}
		r.count++
		changed = append(changed, device)
	}
	r.enforceLimitLocked(at)
	return changed
}

// ForAddresses returns the non-expired domains attributed to any of the given
// device addresses, most recently seen first and de-duplicated by name.
func (r *Registry) ForAddresses(addresses []netip.Addr, now time.Time) []Entry {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	found := make(map[string]Entry)
	for _, address := range addresses {
		for name, entry := range r.byIP[address.Unmap()] {
			if now.Sub(entry.LastSeen) > r.ttl {
				continue
			}
			if existing, ok := found[name]; !ok || entry.LastSeen.After(existing.LastSeen) {
				found[name] = entry
			}
		}
	}
	result := make([]Entry, 0, len(found))
	for _, entry := range found {
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].LastSeen.Equal(result[j].LastSeen) {
			return result[i].Domain < result[j].Domain
		}
		return result[i].LastSeen.After(result[j].LastSeen)
	})
	return result
}

// Prune drops entries idle for longer than the TTL and returns the addresses
// that lost at least one domain.
func (r *Registry) Prune(now time.Time) []netip.Addr {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var changed []netip.Addr
	for address, entries := range r.byIP {
		for name, entry := range entries {
			if now.Sub(entry.LastSeen) > r.ttl {
				delete(entries, name)
				r.count--
				changed = append(changed, address)
			}
		}
		if len(entries) == 0 {
			delete(r.byIP, address)
		}
	}
	return changed
}

// Len reports the total number of tracked entries.
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

// enforceLimitLocked evicts the least recently seen entries when the registry
// grows past its bound. Callers must hold the lock.
func (r *Registry) enforceLimitLocked(now time.Time) {
	if r.count <= r.max {
		return
	}
	for address, entries := range r.byIP {
		for name, entry := range entries {
			if now.Sub(entry.LastSeen) > r.ttl {
				delete(entries, name)
				r.count--
			}
		}
		if len(entries) == 0 {
			delete(r.byIP, address)
		}
	}
	if r.count <= r.max {
		return
	}
	type ref struct {
		address  netip.Addr
		domain   string
		lastSeen time.Time
	}
	refs := make([]ref, 0, r.count)
	for address, entries := range r.byIP {
		for name, entry := range entries {
			refs = append(refs, ref{address, name, entry.LastSeen})
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].lastSeen.Before(refs[j].lastSeen) })
	for _, item := range refs {
		if r.count <= r.max {
			break
		}
		if entries := r.byIP[item.address]; entries != nil {
			if _, ok := entries[item.domain]; ok {
				delete(entries, item.domain)
				r.count--
				if len(entries) == 0 {
					delete(r.byIP, item.address)
				}
			}
		}
	}
}
