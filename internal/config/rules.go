package config

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Preset action identifiers describe the effect of a reusable preset.
const (
	PresetActionDisconnect = "disconnect"
	PresetActionLimit      = "limit"
	PresetActionBlock      = "block"
)

// MaximumPresetBitsPerSecond bounds persisted bandwidth rates. The GUI still
// validates the final policy, but this keeps obviously invalid values out of
// the configuration file.
const MaximumPresetBitsPerSecond = 100_000_000_000

var (
	ErrInvalidPreset      = errors.New("preset is invalid")
	ErrInvalidSchedule    = errors.New("schedule is invalid")
	ErrInvalidDomainBlock = errors.New("domain block list is invalid")
)

// Preset is a named, reusable device action. Disconnect presets carry no
// parameters, limit presets carry bandwidth rates, and block presets carry a
// list of domains to deny.
type Preset struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	Action                string   `json:"action"`
	DownloadBitsPerSecond int64    `json:"download_bits_per_second,omitempty"`
	UploadBitsPerSecond   int64    `json:"upload_bits_per_second,omitempty"`
	Domains               []string `json:"domains,omitempty"`
}

// Schedule applies a preset to selected devices during a recurring weekly
// window. An end time that is not after the start time wraps past midnight.
type Schedule struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Days     []int    `json:"days"`
	Start    string   `json:"start"`
	End      string   `json:"end"`
	PresetID string   `json:"preset_id"`
	MACs     []string `json:"macs"`
}

// PresetList returns a deep copy of the configured presets.
func (config Config) PresetList() []Preset { return clonePresets(config.Presets) }

// ScheduleList returns a deep copy of the configured schedules.
func (config Config) ScheduleList() []Schedule { return cloneSchedules(config.Schedules) }

// DomainBlockMap returns a deep copy of the per-device domain block lists.
func (config Config) DomainBlockMap() map[string][]string {
	return cloneDomainBlocks(config.DomainBlocks)
}

// NormalizeDomains validates and canonicalizes a list of denied hostnames,
// returning an error when any entry is not a conservative printable hostname.
func NormalizeDomains(domains []string) ([]string, error) { return normalizeDomains(domains) }

// BlockedDomains returns the blocked domains recorded for a device.
func (config Config) BlockedDomains(mac net.HardwareAddr) []string {
	key := strings.ToLower(mac.String())
	domains := config.DomainBlocks[key]
	return append([]string(nil), domains...)
}

// SetPresets replaces the preset list and prunes schedules that referenced a
// removed preset.
func (s *Store) SetPresets(presets []Preset) (Config, error) {
	return s.update(func(config *Config) error {
		normalized, err := normalizePresets(presets)
		if err != nil {
			return err
		}
		config.Presets = normalized
		schedules, err := normalizeSchedules(config.Schedules, normalized, false)
		if err != nil {
			return err
		}
		config.Schedules = schedules
		return nil
	})
}

// SetSchedules replaces the schedule list, validating references against the
// stored presets.
func (s *Store) SetSchedules(schedules []Schedule) (Config, error) {
	return s.update(func(config *Config) error {
		normalized, err := normalizeSchedules(schedules, config.Presets, true)
		if err != nil {
			return err
		}
		config.Schedules = normalized
		return nil
	})
}

// SetDomainBlocks records the blocked domains for a device. An empty list
// removes the device entry.
func (s *Store) SetDomainBlocks(mac net.HardwareAddr, domains []string) (Config, error) {
	key, err := normalizeMAC(mac)
	if err != nil {
		return Config{}, err
	}
	normalized, err := normalizeDomains(domains)
	if err != nil {
		return Config{}, err
	}
	return s.update(func(config *Config) error {
		if len(normalized) == 0 {
			delete(config.DomainBlocks, key)
			return nil
		}
		if config.DomainBlocks == nil {
			config.DomainBlocks = make(map[string][]string)
		}
		config.DomainBlocks[key] = normalized
		return nil
	})
}

// RemoveDomainBlocks clears the blocked domains for a device.
func (s *Store) RemoveDomainBlocks(mac net.HardwareAddr) (Config, error) {
	key, err := normalizeMAC(mac)
	if err != nil {
		return Config{}, err
	}
	return s.update(func(config *Config) error {
		delete(config.DomainBlocks, key)
		return nil
	})
}

func normalizePresets(presets []Preset) ([]Preset, error) {
	if len(presets) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(presets))
	result := make([]Preset, 0, len(presets))
	for _, preset := range presets {
		normalized, err := normalizePreset(preset)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[normalized.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate preset id %q", ErrInvalidPreset, normalized.ID)
		}
		seen[normalized.ID] = struct{}{}
		result = append(result, normalized)
	}
	return result, nil
}

func normalizePreset(preset Preset) (Preset, error) {
	preset.ID = strings.TrimSpace(preset.ID)
	preset.Name = strings.TrimSpace(preset.Name)
	if preset.ID == "" || len([]rune(preset.ID)) > 64 {
		return Preset{}, fmt.Errorf("%w: preset id must contain 1 to 64 characters", ErrInvalidPreset)
	}
	if len([]rune(preset.Name)) < 1 || len([]rune(preset.Name)) > 64 {
		return Preset{}, fmt.Errorf("%w: preset name must contain 1 to 64 characters", ErrInvalidPreset)
	}
	switch preset.Action {
	case PresetActionDisconnect:
		preset.DownloadBitsPerSecond, preset.UploadBitsPerSecond, preset.Domains = 0, 0, nil
	case PresetActionLimit:
		if preset.DownloadBitsPerSecond < 0 || preset.UploadBitsPerSecond < 0 {
			return Preset{}, fmt.Errorf("%w: bandwidth rates cannot be negative", ErrInvalidPreset)
		}
		if preset.DownloadBitsPerSecond == 0 && preset.UploadBitsPerSecond == 0 {
			return Preset{}, fmt.Errorf("%w: a bandwidth preset requires at least one rate", ErrInvalidPreset)
		}
		if preset.DownloadBitsPerSecond > MaximumPresetBitsPerSecond || preset.UploadBitsPerSecond > MaximumPresetBitsPerSecond {
			return Preset{}, fmt.Errorf("%w: bandwidth rates exceed the supported maximum", ErrInvalidPreset)
		}
		preset.Domains = nil
	case PresetActionBlock:
		domains, err := normalizeDomains(preset.Domains)
		if err != nil {
			return Preset{}, err
		}
		if len(domains) == 0 {
			return Preset{}, fmt.Errorf("%w: a block preset requires at least one domain", ErrInvalidPreset)
		}
		preset.Domains = domains
		preset.DownloadBitsPerSecond, preset.UploadBitsPerSecond = 0, 0
	default:
		return Preset{}, fmt.Errorf("%w: unsupported action %q", ErrInvalidPreset, preset.Action)
	}
	return preset, nil
}

func normalizeSchedules(schedules []Schedule, presets []Preset, strict bool) ([]Schedule, error) {
	if len(schedules) == 0 {
		return nil, nil
	}
	known := make(map[string]struct{}, len(presets))
	for _, preset := range presets {
		known[preset.ID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(schedules))
	result := make([]Schedule, 0, len(schedules))
	for _, schedule := range schedules {
		normalized, resolvable, err := normalizeSchedule(schedule, known)
		if err != nil {
			return nil, err
		}
		if !resolvable {
			// A schedule referencing a missing preset is dropped rather than
			// failing the whole configuration; unusable schedules are noise.
			if strict {
				return nil, fmt.Errorf("%w: schedule %q references unknown preset %q", ErrInvalidSchedule, schedule.ID, schedule.PresetID)
			}
			continue
		}
		if _, exists := seen[normalized.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate schedule id %q", ErrInvalidSchedule, normalized.ID)
		}
		seen[normalized.ID] = struct{}{}
		result = append(result, normalized)
	}
	return result, nil
}

func normalizeSchedule(schedule Schedule, presets map[string]struct{}) (Schedule, bool, error) {
	schedule.ID = strings.TrimSpace(schedule.ID)
	schedule.Name = strings.TrimSpace(schedule.Name)
	if schedule.ID == "" || len([]rune(schedule.ID)) > 64 {
		return Schedule{}, false, fmt.Errorf("%w: schedule id must contain 1 to 64 characters", ErrInvalidSchedule)
	}
	if len([]rune(schedule.Name)) < 1 || len([]rune(schedule.Name)) > 64 {
		return Schedule{}, false, fmt.Errorf("%w: schedule name must contain 1 to 64 characters", ErrInvalidSchedule)
	}
	schedule.PresetID = strings.TrimSpace(schedule.PresetID)
	if _, ok := presets[schedule.PresetID]; !ok {
		return Schedule{}, false, nil
	}
	start, err := parseClock(schedule.Start)
	if err != nil {
		return Schedule{}, false, fmt.Errorf("%w: %v", ErrInvalidSchedule, err)
	}
	end, err := parseClock(schedule.End)
	if err != nil {
		return Schedule{}, false, fmt.Errorf("%w: %v", ErrInvalidSchedule, err)
	}
	if start == end {
		return Schedule{}, false, fmt.Errorf("%w: start and end times must differ", ErrInvalidSchedule)
	}
	days, err := normalizeDays(schedule.Days)
	if err != nil {
		return Schedule{}, false, err
	}
	schedule.Start, schedule.End, schedule.Days = start, end, days
	macs, err := normalizeMACS(schedule.MACs)
	if err != nil {
		return Schedule{}, false, err
	}
	if len(macs) == 0 {
		return Schedule{}, false, fmt.Errorf("%w: a schedule requires at least one device", ErrInvalidSchedule)
	}
	schedule.MACs = macs
	return schedule, true, nil
}

func normalizeDays(days []int) ([]int, error) {
	seen := make(map[int]struct{}, len(days))
	result := make([]int, 0, len(days))
	for _, day := range days {
		if day < 0 || day > 6 {
			return nil, fmt.Errorf("%w: weekday must be between 0 (Sunday) and 6 (Saturday)", ErrInvalidSchedule)
		}
		if _, exists := seen[day]; exists {
			continue
		}
		seen[day] = struct{}{}
		result = append(result, day)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("%w: a schedule requires at least one weekday", ErrInvalidSchedule)
	}
	return result, nil
}

func normalizeMACS(macs []string) ([]string, error) {
	seen := make(map[string]struct{}, len(macs))
	result := make([]string, 0, len(macs))
	for _, value := range macs {
		parsed, err := net.ParseMAC(strings.TrimSpace(value))
		if err != nil || len(parsed) != 6 {
			return nil, fmt.Errorf("%w: invalid device %q", ErrInvalidSchedule, value)
		}
		key := parsed.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, key)
	}
	return result, nil
}

func normalizeDomains(domains []string) ([]string, error) {
	seen := make(map[string]struct{}, len(domains))
	result := make([]string, 0, len(domains))
	for _, domain := range domains {
		cleaned, ok := sanitizeDomain(domain)
		if !ok {
			return nil, fmt.Errorf("%w: invalid domain %q", ErrInvalidDomainBlock, domain)
		}
		if _, exists := seen[cleaned]; exists {
			continue
		}
		seen[cleaned] = struct{}{}
		result = append(result, cleaned)
	}
	return result, nil
}

func normalizeDomainBlocks(blocks map[string][]string) (map[string][]string, error) {
	if len(blocks) == 0 {
		return nil, nil
	}
	result := make(map[string][]string, len(blocks))
	for mac, domains := range blocks {
		parsed, err := net.ParseMAC(strings.TrimSpace(mac))
		if err != nil || len(parsed) != 6 {
			return nil, fmt.Errorf("%w: invalid device %q", ErrInvalidDomainBlock, mac)
		}
		normalized, err := normalizeDomains(domains)
		if err != nil {
			return nil, err
		}
		if len(normalized) == 0 {
			continue
		}
		result[parsed.String()] = normalized
	}
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

func sanitizeDomain(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	if value == "" || len(value) > 253 || strings.Contains(value, "..") {
		return "", false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			continue
		}
		return "", false
	}
	return value, true
}

func parseClock(value string) (string, error) {
	value = strings.TrimSpace(value)
	parsed, err := time.Parse("15:04", value)
	if err != nil {
		return "", fmt.Errorf("time %q must use HH:MM", value)
	}
	return parsed.Format("15:04"), nil
}

func clonePresets(presets []Preset) []Preset {
	if len(presets) == 0 {
		return nil
	}
	result := make([]Preset, len(presets))
	for i, preset := range presets {
		result[i] = preset
		result[i].Domains = append([]string(nil), preset.Domains...)
	}
	return result
}

func cloneSchedules(schedules []Schedule) []Schedule {
	if len(schedules) == 0 {
		return nil
	}
	result := make([]Schedule, len(schedules))
	for i, schedule := range schedules {
		result[i] = schedule
		result[i].Days = append([]int(nil), schedule.Days...)
		result[i].MACs = append([]string(nil), schedule.MACs...)
	}
	return result
}

func cloneDomainBlocks(blocks map[string][]string) map[string][]string {
	if len(blocks) == 0 {
		return nil
	}
	result := make(map[string][]string, len(blocks))
	for mac, domains := range blocks {
		result[mac] = append([]string(nil), domains...)
	}
	return result
}
