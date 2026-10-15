package app

import (
	"net/netip"
	"sync"
	"time"

	"github.com/amdzy/NetWarden/internal/core"
	"github.com/amdzy/NetWarden/internal/domains"
	"github.com/amdzy/NetWarden/internal/packet"
)

// domainObserver records passive Layer 7 observations and notifies the runtime
// when previously unseen domains appear, so the UI can refresh without the
// observation volume leaking into the activity feed.
type domainObserver struct {
	registry *domains.Registry

	mu      sync.Mutex
	publish func([]netip.Addr)
}

var _ core.DomainObserver = (*domainObserver)(nil)

func (d *domainObserver) ObserveDomains(observations []packet.Observation) {
	changed := d.registry.Observe(observations, time.Now().UTC())
	if len(changed) == 0 {
		return
	}
	d.mu.Lock()
	publish := d.publish
	d.mu.Unlock()
	if publish != nil {
		publish(changed)
	}
}

func (d *domainObserver) setPublish(publish func([]netip.Addr)) {
	d.mu.Lock()
	d.publish = publish
	d.mu.Unlock()
}

// DeviceDomains returns the domains recently attributed to a device, newest
// first. It returns nothing when the runtime is not configured for capture.
func (r *Runtime) DeviceDomains(mac string) []domains.Entry {
	if r.domains == nil {
		return nil
	}
	current, ok := r.registry.Get(mac)
	if !ok {
		return nil
	}
	return r.domains.ForAddresses(current.Addresses, time.Now().UTC())
}

func (r *Runtime) publishDomains(_ []netip.Addr) {
	r.publish(Event{Kind: EventDeviceDomainsObserved})
}
