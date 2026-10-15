package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	appconfig "github.com/amdzy/NetWarden/internal/config"
	"github.com/amdzy/NetWarden/internal/device"
)

type recordingDomainBlockController struct {
	mu           sync.Mutex
	set          []DomainBlockTarget
	setAddresses [][]netip.Addr
	removed      []net.HardwareAddr
	setErr       error
	remErr       error
}

func (c *recordingDomainBlockController) SetDeviceBlock(_ context.Context, addresses []netip.Addr, mac net.HardwareAddr, domains []string) error {
	if c.setErr != nil {
		return c.setErr
	}
	c.mu.Lock()
	c.setAddresses = append(c.setAddresses, append([]netip.Addr(nil), addresses...))
	c.set = append(c.set, DomainBlockTarget{MAC: append(net.HardwareAddr(nil), mac...), Addresses: append([]netip.Addr(nil), addresses...), Domains: append([]string(nil), domains...)})
	c.mu.Unlock()
	return nil
}

func (c *recordingDomainBlockController) RemoveDeviceBlock(_ context.Context, mac net.HardwareAddr) error {
	if c.remErr != nil {
		return c.remErr
	}
	c.mu.Lock()
	c.removed = append(c.removed, append(net.HardwareAddr(nil), mac...))
	c.mu.Unlock()
	return nil
}

type recordingDomainPath struct {
	mu         sync.Mutex
	monitored  map[string]bool
	limited    map[string]bool
	startCalls int
	stopCalls  int
}

func newRecordingDomainPath() *recordingDomainPath {
	return &recordingDomainPath{monitored: make(map[string]bool), limited: make(map[string]bool)}
}

func (p *recordingDomainPath) StartMonitoring(_ context.Context, target ControlTarget) error {
	p.mu.Lock()
	p.monitored[target.MAC.String()] = true
	p.startCalls++
	p.mu.Unlock()
	return nil
}

func (p *recordingDomainPath) StopMonitoring(_ context.Context, mac net.HardwareAddr) error {
	p.mu.Lock()
	delete(p.monitored, mac.String())
	p.stopCalls++
	p.mu.Unlock()
	return nil
}

func (p *recordingDomainPath) Contains(mac net.HardwareAddr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.monitored[mac.String()] || p.limited[mac.String()]
}

func (p *recordingDomainPath) Limited(mac net.HardwareAddr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.limited[mac.String()]
}

func TestDomainBlockServiceInstallsPathAndNormalizedDomains(t *testing.T) {
	registry, target := bandwidthRegistry(t)
	controller := &recordingDomainBlockController{}
	path := newRecordingDomainPath()
	service := NewDomainBlockService(controller, path, registry, nil)
	if err := service.Set(context.Background(), target, []string{"Ads.Example.com", "ads.example.com", "bad.example.com"}); err != nil {
		t.Fatal(err)
	}
	if len(controller.set) != 1 || len(controller.set[0].Domains) != 2 || controller.set[0].Domains[0] != "ads.example.com" || controller.set[0].Domains[1] != "bad.example.com" {
		t.Fatalf("installed domains = %#v", controller.set)
	}
	if path.startCalls != 1 || !path.Contains(target.MAC) {
		t.Fatalf("path was not prepared: starts=%d", path.startCalls)
	}
	snapshot := service.Snapshot()
	if len(snapshot) != 1 || snapshot[0].IP != target.IP || len(snapshot[0].Addresses) != 1 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	if domains := service.Domains(target.MAC); len(domains) != 2 || !service.Contains(target.MAC) {
		t.Fatalf("domains = %#v contains = %t", domains, service.Contains(target.MAC))
	}
	if err := service.Remove(context.Background(), target.MAC); err != nil {
		t.Fatal(err)
	}
	if len(controller.removed) != 1 || path.stopCalls != 1 || len(service.Snapshot()) != 0 {
		t.Fatalf("removals=%#v stops=%d active=%#v", controller.removed, path.stopCalls, service.Snapshot())
	}
}

func TestDomainBlockServiceLeavesPreExistingPathAlone(t *testing.T) {
	registry, target := bandwidthRegistry(t)
	controller := &recordingDomainBlockController{}
	path := newRecordingDomainPath()
	path.monitored[target.MAC.String()] = true
	service := NewDomainBlockService(controller, path, registry, nil)
	if err := service.Set(context.Background(), target, []string{"ads.example.com"}); err != nil {
		t.Fatal(err)
	}
	if path.startCalls != 0 {
		t.Fatalf("reused path was re-monitored: starts=%d", path.startCalls)
	}
	if err := service.Remove(context.Background(), target.MAC); err != nil {
		t.Fatal(err)
	}
	if path.stopCalls != 0 || !path.Contains(target.MAC) {
		t.Fatalf("removal disturbed a pre-existing path: stops=%d", path.stopCalls)
	}
}

func TestDomainBlockServiceKeepsPathForActiveLimit(t *testing.T) {
	registry, target := bandwidthRegistry(t)
	controller := &recordingDomainBlockController{}
	path := newRecordingDomainPath()
	service := NewDomainBlockService(controller, path, registry, nil)
	if err := service.Set(context.Background(), target, []string{"ads.example.com"}); err != nil {
		t.Fatal(err)
	}
	path.limited[target.MAC.String()] = true
	if err := service.Remove(context.Background(), target.MAC); err != nil {
		t.Fatal(err)
	}
	if path.stopCalls != 0 || len(service.Snapshot()) != 0 {
		t.Fatalf("limited path was stopped by block removal: stops=%d", path.stopCalls)
	}
}

func TestDomainBlockServiceRejectsUnavailableConflictingAndUnsafeTargets(t *testing.T) {
	registry, target := bandwidthRegistry(t)
	if err := NewDomainBlockService(nil, newRecordingDomainPath(), registry, nil).Set(context.Background(), target, []string{"ads.example.com"}); !errors.Is(err, ErrDomainBlockUnavailable) {
		t.Fatalf("unavailable error = %v", err)
	}
	conflicting := NewDomainBlockService(&recordingDomainBlockController{}, newRecordingDomainPath(), registry, func(net.HardwareAddr) bool { return true })
	if err := conflicting.Set(context.Background(), target, []string{"ads.example.com"}); !errors.Is(err, ErrDomainBlockConflict) {
		t.Fatalf("conflict error = %v", err)
	}
	path := newRecordingDomainPath()
	service := NewDomainBlockService(&recordingDomainBlockController{}, path, registry, nil)
	if err := service.Set(context.Background(), target, []string{"bad domain"}); !errors.Is(err, appconfig.ErrInvalidDomainBlock) {
		t.Fatalf("invalid domain error = %v", err)
	}
	if path.startCalls != 0 || len(service.Snapshot()) != 0 {
		t.Fatal("invalid domains touched helper state")
	}
	unknown := ControlTarget{IP: netip.MustParseAddr("192.168.1.99"), MAC: target.MAC}
	if err := service.Set(context.Background(), unknown, []string{"ads.example.com"}); !errors.Is(err, ErrDomainBlockTarget) {
		t.Fatalf("identity error = %v", err)
	}
}

func TestDomainBlockServiceRollsBackPathWhenInstallFails(t *testing.T) {
	registry, target := bandwidthRegistry(t)
	controller := &recordingDomainBlockController{setErr: errors.New("install failed")}
	path := newRecordingDomainPath()
	service := NewDomainBlockService(controller, path, registry, nil)
	if err := service.Set(context.Background(), target, []string{"ads.example.com"}); err == nil {
		t.Fatal("expected install failure")
	}
	if path.stopCalls != 1 || len(service.Snapshot()) != 0 {
		t.Fatalf("failed install left the path active: stops=%d", path.stopCalls)
	}
}

func TestDomainBlockServiceReconcilesAddressChanges(t *testing.T) {
	registry, target := bandwidthRegistry(t)
	controller := &recordingDomainBlockController{}
	path := newRecordingDomainPath()
	service := NewDomainBlockService(controller, path, registry, nil)
	if err := service.Set(context.Background(), target, []string{"ads.example.com"}); err != nil {
		t.Fatal(err)
	}
	ipv6 := netip.MustParseAddr("2001:db8:1::20")
	current, _, err := registry.Observe(device.Observation{IP: ipv6, MAC: target.MAC, SeenAt: time.Now().Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ReconcileDevice(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if len(controller.setAddresses) != 2 || len(controller.setAddresses[1]) != 2 {
		t.Fatalf("reconciled addresses = %#v", controller.setAddresses)
	}
}

func TestDomainBlockServiceEmptyListClears(t *testing.T) {
	registry, target := bandwidthRegistry(t)
	controller := &recordingDomainBlockController{}
	path := newRecordingDomainPath()
	service := NewDomainBlockService(controller, path, registry, nil)
	if err := service.Set(context.Background(), target, []string{"ads.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := service.Set(context.Background(), target, nil); err != nil {
		t.Fatal(err)
	}
	if len(service.Snapshot()) != 0 || len(controller.removed) != 1 {
		t.Fatalf("empty list did not clear: %#v", service.Snapshot())
	}
}

type fakeConfiguredBlocks struct {
	mu    sync.Mutex
	store map[string][]string
}

func newFakeConfiguredBlocks() *fakeConfiguredBlocks {
	return &fakeConfiguredBlocks{store: make(map[string][]string)}
}

func (f *fakeConfiguredBlocks) ConfiguredBlockedDomains(mac net.HardwareAddr) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.store[strings.ToLower(mac.String())]...), nil
}

func (f *fakeConfiguredBlocks) SetDomainBlocks(mac net.HardwareAddr, domains []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.ToLower(mac.String())
	if len(domains) == 0 {
		delete(f.store, key)
		return nil
	}
	f.store[key] = append([]string(nil), domains...)
	return nil
}

func (f *fakeConfiguredBlocks) RemoveDomainBlocks(mac net.HardwareAddr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.store, strings.ToLower(mac.String()))
	return nil
}

func (f *fakeConfiguredBlocks) domains(mac net.HardwareAddr) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.store[strings.ToLower(mac.String())]...)
}

func TestDomainBlockServicePersistsAndClearsConfiguredBlocks(t *testing.T) {
	registry, target := bandwidthRegistry(t)
	controller := &recordingDomainBlockController{}
	path := newRecordingDomainPath()
	configured := newFakeConfiguredBlocks()
	service := NewDomainBlockService(controller, path, registry, nil)
	service.SetConfiguredSource(configured)
	if err := service.Set(context.Background(), target, []string{"Ads.Example.com"}); err != nil {
		t.Fatal(err)
	}
	if domains := configured.domains(target.MAC); len(domains) != 1 || domains[0] != "ads.example.com" {
		t.Fatalf("persisted domains = %#v", domains)
	}
	if err := service.Remove(context.Background(), target.MAC); err != nil {
		t.Fatal(err)
	}
	if domains := configured.domains(target.MAC); len(domains) != 0 {
		t.Fatalf("removal did not clear persisted domains = %#v", domains)
	}
}

func TestDomainBlockServiceReappliesConfiguredBlockOnReconcile(t *testing.T) {
	registry, target := bandwidthRegistry(t)
	configured := newFakeConfiguredBlocks()
	if err := configured.SetDomainBlocks(target.MAC, []string{"ads.example.com", "tracker.example.com"}); err != nil {
		t.Fatal(err)
	}

	controller := &recordingDomainBlockController{}
	path := newRecordingDomainPath()
	service := NewDomainBlockService(controller, path, registry, nil)
	service.SetConfiguredSource(configured)
	current, found := registry.Get(target.MAC.String())
	if !found {
		t.Fatal("device missing from registry")
	}
	if err := service.ReconcileDevice(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if len(controller.set) != 1 || len(controller.set[0].Domains) != 2 {
		t.Fatalf("configured block was not re-applied: %#v", controller.set)
	}
	if path.startCalls != 1 || !service.Contains(target.MAC) {
		t.Fatalf("configured block did not prepare the path: starts=%d", path.startCalls)
	}

	other, _ := net.ParseMAC("02:00:00:00:00:21")
	otherTarget := ControlTarget{IP: netip.MustParseAddr("192.168.1.21"), MAC: other}
	if _, _, err := registry.Observe(device.Observation{IP: otherTarget.IP, MAC: other, SeenAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	otherDevice, _ := registry.Get(other.String())
	if err := service.ReconcileDevice(context.Background(), otherDevice); err != nil {
		t.Fatal(err)
	}
	if len(controller.set) != 1 {
		t.Fatalf("device without a configured block was wrongly installed: %#v", controller.set)
	}
}

func TestDomainBlockServiceRollsBackPersistedBlockWhenInstallFails(t *testing.T) {
	registry, target := bandwidthRegistry(t)
	configured := newFakeConfiguredBlocks()
	if err := configured.SetDomainBlocks(target.MAC, []string{"old.example.com"}); err != nil {
		t.Fatal(err)
	}
	controller := &recordingDomainBlockController{setErr: errors.New("install failed")}
	service := NewDomainBlockService(controller, newRecordingDomainPath(), registry, nil)
	service.SetConfiguredSource(configured)
	if err := service.Set(context.Background(), target, []string{"ads.example.com"}); err == nil {
		t.Fatal("expected install failure")
	}
	if domains := configured.domains(target.MAC); len(domains) != 1 || domains[0] != "old.example.com" {
		t.Fatalf("failed install did not restore persisted domains: %#v", domains)
	}
}
