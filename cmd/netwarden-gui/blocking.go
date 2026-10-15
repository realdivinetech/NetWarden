package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	coreapp "github.com/amdzy/NetWarden/internal/app"
	appconfig "github.com/amdzy/NetWarden/internal/config"
)

type DomainBlockDTO struct {
	IP      string   `json:"ip"`
	MAC     string   `json:"mac"`
	Domains []string `json:"domains"`
	Active  bool     `json:"active"`
}

// DomainBlocks merges the persisted per-device deny lists with the deny lists
// currently installed in the helper, so the UI can show intent and enforcement
// separately.
func (a *GUIApp) DomainBlocks() ([]DomainBlockDTO, error) {
	_, config, err := loadSettings()
	if err != nil {
		return nil, err
	}
	blocks := make(map[string]*DomainBlockDTO)
	for mac, domains := range config.DomainBlockMap() {
		key := strings.ToLower(mac)
		blocks[key] = &DomainBlockDTO{MAC: mac, Domains: append([]string(nil), domains...)}
	}
	a.mu.RLock()
	supervisor := a.supervisor
	a.mu.RUnlock()
	if supervisor != nil && supervisor.Current() != nil {
		for _, target := range supervisor.Current().DomainBlocks() {
			key := strings.ToLower(target.MAC.String())
			item := blocks[key]
			if item == nil {
				item = &DomainBlockDTO{MAC: target.MAC.String()}
				blocks[key] = item
			}
			item.IP = target.IP.String()
			item.Domains = append([]string(nil), target.Domains...)
			item.Active = true
		}
	}
	if len(blocks) > 0 {
		if snapshot, loadErr := loadHistorySnapshot(); loadErr == nil {
			for _, current := range snapshot.Devices {
				if item := blocks[strings.ToLower(current.MAC)]; item != nil && item.IP == "" {
					item.IP = current.IP.String()
				}
			}
		}
	}
	result := make([]DomainBlockDTO, 0, len(blocks))
	for _, item := range blocks {
		result = append(result, *item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].MAC < result[j].MAC })
	return result, nil
}

// SetDomainBlock installs (or replaces) a device deny list. While monitoring is
// running the list is enforced immediately; otherwise it is persisted and
// re-applied the next time the device comes online.
func (a *GUIApp) SetDomainBlock(ipText, macText string, domains []string) error {
	if err := a.requireAuthorized(); err != nil {
		return err
	}
	mac, err := net.ParseMAC(macText)
	if err != nil {
		return fmt.Errorf("parse target MAC: %w", err)
	}
	normalized, err := appconfig.NormalizeDomains(domains)
	if err != nil {
		return err
	}
	if len(normalized) == 0 {
		return a.RemoveDomainBlock(macText)
	}
	runtime, err := a.activeRuntime()
	if err != nil {
		store, _, loadErr := loadSettings()
		if loadErr != nil {
			return loadErr
		}
		_, err = store.SetDomainBlocks(mac, normalized)
		a.logBlockResult("set", ipText, macText, err)
		return err
	}
	ip, err := netip.ParseAddr(ipText)
	if err != nil {
		return fmt.Errorf("parse target IP: %w", err)
	}
	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()
	err = runtime.SetDomainBlock(ctx, coreapp.ControlTarget{IP: ip, MAC: mac}, normalized)
	a.logBlockResult("set", ipText, macText, err)
	return err
}

// RemoveDomainBlock clears a device deny list, stopping enforcement if the
// device is being monitored.
func (a *GUIApp) RemoveDomainBlock(macText string) error {
	if err := a.requireAuthorized(); err != nil {
		return err
	}
	mac, err := net.ParseMAC(macText)
	if err != nil {
		return fmt.Errorf("parse target MAC: %w", err)
	}
	runtime, err := a.activeRuntime()
	if err != nil {
		store, _, loadErr := loadSettings()
		if loadErr != nil {
			return loadErr
		}
		_, err = store.RemoveDomainBlocks(mac)
		a.logBlockResult("remove", "", macText, err)
		return err
	}
	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()
	err = runtime.RemoveDomainBlock(ctx, mac)
	a.logBlockResult("remove", "", macText, err)
	return err
}

// ClearDomainBlocks removes every device deny list, both persisted and active.
func (a *GUIApp) ClearDomainBlocks() error {
	if runtime, err := a.activeRuntime(); err == nil {
		ctx, cancel := context.WithTimeout(a.ctx, 15*time.Second)
		defer cancel()
		err = runtime.ClearDomainBlocks(ctx)
		a.logBlockResult("clear", "", "", err)
		return err
	}
	store, config, err := loadSettings()
	if err != nil {
		return err
	}
	var result error
	for macText := range config.DomainBlockMap() {
		mac, parseErr := net.ParseMAC(macText)
		if parseErr != nil {
			continue
		}
		if _, removeErr := store.RemoveDomainBlocks(mac); removeErr != nil {
			result = fmt.Errorf("remove block for %s: %w", macText, removeErr)
		}
	}
	a.logBlockResult("clear", "", "", result)
	return result
}

func (a *GUIApp) logBlockResult(operation, ip, mac string, err error) {
	level, message := slog.LevelInfo, "domain block action completed"
	if err != nil {
		level, message = slog.LevelError, "domain block action failed"
	}
	a.log(level, message, "component", "domain_block", "operation", operation, "ip", ip, "mac", mac, "error", err)
}
