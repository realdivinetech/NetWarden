package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	appconfig "github.com/amdzy/NetWarden/internal/config"
	"github.com/amdzy/NetWarden/internal/device"
)

var (
	ErrDomainBlockUnavailable = errors.New("domain blocking is unavailable for the active capture backend")
	ErrDomainBlockConflict    = errors.New("device has an active disconnect control")
	ErrDomainBlockTarget      = errors.New("domain block target is not an eligible online peer")
)

// DomainBlockController installs per-device deny lists in the privileged
// helper. Only hostnames cross the process boundary.
type DomainBlockController interface {
	SetDeviceBlock(context.Context, []netip.Addr, net.HardwareAddr, []string) error
	RemoveDeviceBlock(context.Context, net.HardwareAddr) error
}

// domainPathController keeps a blocked device on the capture path so the helper
// can observe and drop its DNS/TLS traffic.
type domainPathController interface {
	StartMonitoring(context.Context, ControlTarget) error
	StopMonitoring(context.Context, net.HardwareAddr) error
	Contains(net.HardwareAddr) bool
	Limited(net.HardwareAddr) bool
}

// ConfiguredBlockSource persists per-device deny lists so they survive runtime
// rebuilds and can be re-applied when a device next comes online.
type ConfiguredBlockSource interface {
	ConfiguredBlockedDomains(net.HardwareAddr) ([]string, error)
	SetDomainBlocks(net.HardwareAddr, []string) error
	RemoveDomainBlocks(net.HardwareAddr) error
}

// DomainBlockTarget is the application view of an active per-device deny list.
type DomainBlockTarget struct {
	IP        netip.Addr       `json:"ip"`
	Addresses []netip.Addr     `json:"addresses,omitempty"`
	MAC       net.HardwareAddr `json:"mac"`
	Domains   []string         `json:"domains"`
}

// DomainBlockService owns the application view of helper deny lists for one
// runtime generation. Deny lists are persisted through an optional configured
// source so they can be re-applied to the next runtime generation.
type DomainBlockService struct {
	controller DomainBlockController
	path       domainPathController
	devices    bandwidthDeviceSource
	conflicted func(net.HardwareAddr) bool
	configured ConfiguredBlockSource

	opMu    sync.Mutex
	mu      sync.RWMutex
	active  map[string]DomainBlockTarget
	started map[string]bool
}

func NewDomainBlockService(controller DomainBlockController, path domainPathController, devices bandwidthDeviceSource, conflicted func(net.HardwareAddr) bool) *DomainBlockService {
	return &DomainBlockService{controller: controller, path: path, devices: devices, conflicted: conflicted,
		active: make(map[string]DomainBlockTarget), started: make(map[string]bool)}
}

// SetConfiguredSource wires a persistence source so deny lists survive runtime
// rebuilds and are re-applied the next time a device comes online.
func (s *DomainBlockService) SetConfiguredSource(source ConfiguredBlockSource) {
	if s == nil {
		return
	}
	s.configured = source
}

func (s *DomainBlockService) Available() bool {
	return s != nil && s.controller != nil && s.path != nil
}

// Set installs (or replaces) a device deny list. An empty list removes the
// block, matching the "clear" semantics used elsewhere in the application.
func (s *DomainBlockService) Set(ctx context.Context, target ControlTarget, domains []string) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if !s.Available() {
		return ErrDomainBlockUnavailable
	}
	normalized, err := appconfig.NormalizeDomains(domains)
	if err != nil {
		return fmt.Errorf("domain block: %w", err)
	}
	if len(normalized) == 0 {
		return s.remove(ctx, target.MAC)
	}
	resolved, err := s.resolve(target)
	if err != nil {
		return err
	}
	if s.conflicted != nil && s.conflicted(resolved.MAC) {
		return ErrDomainBlockConflict
	}
	previous, hadPrevious, err := s.persist(resolved.MAC, normalized)
	if err != nil {
		return err
	}
	if err := s.install(ctx, resolved, normalized); err != nil {
		s.restorePersisted(resolved.MAC, previous, hadPrevious)
		return err
	}
	return nil
}

// install starts the capture path if needed and pushes the deny list to the
// helper, recording the active target. Callers hold opMu.
func (s *DomainBlockService) install(ctx context.Context, resolved DomainBlockTarget, domains []string) error {
	key := resolved.MAC.String()
	startedMonitor := false
	if !s.path.Contains(resolved.MAC) {
		if err := s.path.StartMonitoring(ctx, ControlTarget{IP: resolved.IP, MAC: resolved.MAC}); err != nil {
			return fmt.Errorf("prepare domain block path: %w", err)
		}
		startedMonitor = true
	}
	if err := s.controller.SetDeviceBlock(ctx, resolved.Addresses, resolved.MAC, domains); err != nil {
		if startedMonitor {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.path.StopMonitoring(rollbackCtx, resolved.MAC)
			cancel()
		}
		return fmt.Errorf("set domain block: %w", err)
	}
	resolved.Domains = domains
	s.mu.Lock()
	_, existed := s.active[key]
	previousStarted := s.started[key]
	s.active[key] = resolved
	if startedMonitor || !existed {
		s.started[key] = startedMonitor
	} else {
		s.started[key] = previousStarted
	}
	s.mu.Unlock()
	return nil
}

// persist records the deny list in the configured source, returning the prior
// value so a failed install can be rolled back.
func (s *DomainBlockService) persist(mac net.HardwareAddr, domains []string) ([]string, bool, error) {
	if s.configured == nil {
		return nil, false, nil
	}
	previous, err := s.configured.ConfiguredBlockedDomains(mac)
	if err != nil {
		return nil, false, err
	}
	if err := s.configured.SetDomainBlocks(mac, domains); err != nil {
		return nil, false, err
	}
	return previous, len(previous) > 0, nil
}

func (s *DomainBlockService) restorePersisted(mac net.HardwareAddr, previous []string, hadPrevious bool) {
	if s.configured == nil {
		return
	}
	if hadPrevious {
		_ = s.configured.SetDomainBlocks(mac, previous)
		return
	}
	_ = s.configured.RemoveDomainBlocks(mac)
}

// Remove clears a device deny list and stops the monitoring this service
// started, unless a bandwidth limit now keeps the device on the path.
func (s *DomainBlockService) Remove(ctx context.Context, mac net.HardwareAddr) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.remove(ctx, mac)
}

func (s *DomainBlockService) remove(ctx context.Context, mac net.HardwareAddr) error {
	if !s.Available() {
		return ErrDomainBlockUnavailable
	}
	key, err := blockMACKey(mac)
	if err != nil {
		return err
	}
	s.mu.RLock()
	_, found := s.active[key]
	started := s.started[key]
	s.mu.RUnlock()
	if found {
		if err := s.controller.RemoveDeviceBlock(ctx, mac); err != nil {
			return fmt.Errorf("remove domain block: %w", err)
		}
		if started && !s.path.Limited(mac) {
			if err := s.path.StopMonitoring(ctx, mac); err != nil {
				return fmt.Errorf("stop domain block monitoring: %w", err)
			}
		}
		s.mu.Lock()
		delete(s.active, key)
		delete(s.started, key)
		s.mu.Unlock()
	}
	if s.configured != nil {
		_ = s.configured.RemoveDomainBlocks(mac)
	}
	return nil
}

func (s *DomainBlockService) Clear(ctx context.Context) error {
	if !s.Available() {
		return nil
	}
	var result error
	for _, target := range s.Snapshot() {
		if err := s.Remove(ctx, target.MAC); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (s *DomainBlockService) Snapshot() []DomainBlockTarget {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	result := make([]DomainBlockTarget, 0, len(s.active))
	for _, target := range s.active {
		target.MAC = append(net.HardwareAddr(nil), target.MAC...)
		target.Addresses = append([]netip.Addr(nil), target.Addresses...)
		target.Domains = append([]string(nil), target.Domains...)
		result = append(result, target)
	}
	s.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].MAC.String() < result[j].MAC.String() })
	return result
}

func (s *DomainBlockService) Contains(mac net.HardwareAddr) bool {
	if s == nil {
		return false
	}
	key, err := blockMACKey(mac)
	if err != nil {
		return false
	}
	s.mu.RLock()
	_, found := s.active[key]
	s.mu.RUnlock()
	return found
}

func (s *DomainBlockService) Domains(mac net.HardwareAddr) []string {
	if s == nil {
		return nil
	}
	key, err := blockMACKey(mac)
	if err != nil {
		return nil
	}
	s.mu.RLock()
	target, found := s.active[key]
	s.mu.RUnlock()
	if !found {
		return nil
	}
	return append([]string(nil), target.Domains...)
}

func (s *DomainBlockService) ReconcileDevice(ctx context.Context, current device.Device) error {
	if s == nil || !s.Available() {
		return nil
	}
	mac, err := net.ParseMAC(current.MAC)
	if err != nil || !current.Online || current.Role != device.RolePeer {
		return nil
	}
	key, _ := blockMACKey(mac)
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.RLock()
	target, active := s.active[key]
	s.mu.RUnlock()
	if active {
		addresses := eligibleBandwidthAddresses(current)
		if sameAddresses(target.Addresses, addresses) {
			return nil
		}
		if err := s.controller.SetDeviceBlock(ctx, addresses, mac, target.Domains); err != nil {
			return fmt.Errorf("move domain block to new address: %w", err)
		}
		target.IP = current.IP
		target.Addresses = addresses
		s.mu.Lock()
		s.active[key] = target
		s.mu.Unlock()
		return nil
	}
	if s.configured == nil {
		return nil
	}
	configured, err := s.configured.ConfiguredBlockedDomains(mac)
	if err != nil {
		return err
	}
	if len(configured) == 0 || s.conflicted != nil && s.conflicted(mac) {
		return nil
	}
	addresses := eligibleBandwidthAddresses(current)
	if len(addresses) == 0 {
		return nil
	}
	return s.install(ctx, DomainBlockTarget{IP: current.IP, Addresses: addresses, MAC: mac}, configured)
}

func (s *DomainBlockService) resolve(target ControlTarget) (DomainBlockTarget, error) {
	key, err := blockMACKey(target.MAC)
	if err != nil || !target.IP.IsValid() {
		return DomainBlockTarget{}, ErrDomainBlockTarget
	}
	current, found := s.devices.Get(key)
	if !found || !current.Online || current.Role != device.RolePeer || current.IP != target.IP {
		return DomainBlockTarget{}, ErrDomainBlockTarget
	}
	mac, err := net.ParseMAC(current.MAC)
	if err != nil {
		return DomainBlockTarget{}, ErrDomainBlockTarget
	}
	addresses := eligibleBandwidthAddresses(current)
	if len(addresses) == 0 {
		return DomainBlockTarget{}, ErrDomainBlockTarget
	}
	return DomainBlockTarget{IP: current.IP, Addresses: addresses, MAC: mac}, nil
}

func blockMACKey(mac net.HardwareAddr) (string, error) {
	if len(mac) != 6 || mac[0]&1 != 0 {
		return "", ErrDomainBlockTarget
	}
	return mac.String(), nil
}
