// Package config persists user-owned NetWarden configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const CurrentVersion = 6

const (
	DefaultScanIntervalSeconds  = 10
	DefaultOfflineAfterSeconds  = 60
	DefaultHistoryRetentionDays = 90
)

var (
	ErrUnsupportedVersion = errors.New("unsupported configuration version")
	ErrInvalidNickname    = errors.New("nickname must contain 1 to 64 characters")
	ErrCorrupt            = errors.New("configuration is corrupt")
	ErrLock               = errors.New("configuration lock failed")
)

type Config struct {
	Version              int               `json:"version"`
	Interface            string            `json:"interface,omitempty"`
	GatewayMAC           string            `json:"gateway_mac,omitempty"`
	Nicknames            map[string]string `json:"nicknames,omitempty"`
	ScanIntervalSeconds  int               `json:"scan_interval_seconds"`
	OfflineAfterSeconds  int               `json:"offline_after_seconds"`
	HistoryRetentionDays int               `json:"history_retention_days"`
	AutoStart            bool              `json:"auto_start,omitempty"`
	PeriodicDiscovery    bool              `json:"periodic_discovery"`
	NotificationsEnabled bool              `json:"notifications_enabled"`
	NotifyNewDevices     bool              `json:"notify_new_devices"`
	NotifyKnownDevices   bool              `json:"notify_known_devices"`
	NotifyDeviceOffline  bool              `json:"notify_device_offline"`
	NotifySuspicious     bool              `json:"notify_suspicious"`
	Presets              []Preset          `json:"presets,omitempty"`
	Schedules            []Schedule        `json:"schedules,omitempty"`
	DomainBlocks         map[string][]string `json:"domain_blocks,omitempty"`
	GatewayAuth          *GatewayAuthRecord `json:"gateway_auth,omitempty"`
}

// GatewayAuthRecord is the proof that the operator passed the gateway
// authorization gate for one network. It never contains the router password:
// only a protected random secret and its HMAC bound to the gateway identity.
type GatewayAuthRecord struct {
	AuthorizedAt time.Time `json:"authorized_at"`
	GatewayIP    string    `json:"gateway_ip"`
	LocalIP      string    `json:"local_ip,omitempty"`
	GatewayMAC   string    `json:"gateway_mac,omitempty"`
	Strategy     string    `json:"strategy"`
	Verified     bool      `json:"verified"`
	Secret       string    `json:"secret"`
	Proof        string    `json:"proof"`
}

type NotificationSettings struct {
	Enabled           bool `json:"enabled"`
	NewDevices        bool `json:"newDevices"`
	KnownDevices      bool `json:"knownDevices"`
	DeviceOffline     bool `json:"deviceOffline"`
	SuspiciousDevices bool `json:"suspiciousDevices"`
}

func (s *Store) SetNotificationSettings(settings NotificationSettings) (Config, error) {
	return s.update(func(config *Config) error {
		config.NotificationsEnabled = settings.Enabled
		config.NotifyNewDevices = settings.NewDevices
		config.NotifyKnownDevices = settings.KnownDevices
		config.NotifyDeviceOffline = settings.DeviceOffline
		config.NotifySuspicious = settings.SuspiciousDevices
		return nil
	})
}

type MonitoringSettings struct {
	ScanIntervalSeconds  int  `json:"scanIntervalSeconds"`
	OfflineAfterSeconds  int  `json:"offlineAfterSeconds"`
	HistoryRetentionDays int  `json:"historyRetentionDays"`
	AutoStart            bool `json:"autoStart"`
	PeriodicDiscovery    bool `json:"periodicDiscovery"`
}

func (s *Store) SetMonitoringSettings(settings MonitoringSettings) (Config, error) {
	if err := validateMonitoringSettings(settings); err != nil {
		return Config{}, err
	}
	return s.update(func(config *Config) error {
		config.ScanIntervalSeconds = settings.ScanIntervalSeconds
		config.OfflineAfterSeconds = settings.OfflineAfterSeconds
		config.HistoryRetentionDays = settings.HistoryRetentionDays
		config.AutoStart = settings.AutoStart
		config.PeriodicDiscovery = settings.PeriodicDiscovery
		return nil
	})
}

func (s *Store) SetGatewayMAC(mac net.HardwareAddr) (Config, error) {
	key, err := normalizeMAC(mac)
	if err != nil {
		return Config{}, err
	}
	return s.update(func(config *Config) error {
		config.GatewayMAC = key
		return nil
	})
}

func (s *Store) RemoveGatewayMAC() (Config, error) {
	return s.update(func(config *Config) error {
		config.GatewayMAC = ""
		return nil
	})
}

// SetGatewayAuth stores the gateway authorization record; a nil record clears
// it, forcing the operator through the authorization gate again.
func (s *Store) SetGatewayAuth(record *GatewayAuthRecord) (Config, error) {
	if record != nil {
		normalized, err := normalizeGatewayAuth(record)
		if err != nil {
			return Config{}, err
		}
		record = normalized
	}
	return s.update(func(config *Config) error {
		config.GatewayAuth = record
		return nil
	})
}

func normalizeGatewayAuth(record *GatewayAuthRecord) (*GatewayAuthRecord, error) {
	if record == nil {
		return nil, nil
	}
	normalized := *record
	normalized.GatewayIP = strings.ToLower(strings.TrimSpace(record.GatewayIP))
	normalized.GatewayMAC = strings.ToLower(strings.TrimSpace(record.GatewayMAC))
	normalized.LocalIP = strings.ToLower(strings.TrimSpace(record.LocalIP))
	if normalized.GatewayIP == "" || normalized.Secret == "" || normalized.Proof == "" {
		return nil, errors.New("gateway authorization record is incomplete")
	}
	if net.ParseIP(normalized.GatewayIP) == nil {
		return nil, errors.New("gateway authorization record has an invalid address")
	}
	return &normalized, nil
}

func DefaultPath() (string, error) {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user configuration directory: %w", err)
	}
	return filepath.Join(directory, "netwarden", "config.json"), nil
}

type Store struct {
	path string
	mu   sync.Mutex
}

func NewStore(path string) *Store { return &Store{path: path} }

func (s *Store) Path() string { return s.path }

func (s *Store) Load() (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := lockFile(s.path + ".lock")
	if err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrLock, err)
	}
	defer unlock()
	return s.load()
}

// ConfiguredBlockedDomains returns the persisted deny list for a device,
// loading the current configuration from disk.
func (s *Store) ConfiguredBlockedDomains(mac net.HardwareAddr) ([]string, error) {
	config, err := s.Load()
	if err != nil {
		return nil, err
	}
	return config.BlockedDomains(mac), nil
}

func (s *Store) SetInterface(name string) (Config, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Config{}, errors.New("interface name cannot be empty")
	}
	return s.update(func(config *Config) error {
		config.Interface = name
		return nil
	})
}

func (s *Store) SetNickname(mac net.HardwareAddr, nickname string) (Config, error) {
	nickname = strings.TrimSpace(nickname)
	if len([]rune(nickname)) < 1 || len([]rune(nickname)) > 64 {
		return Config{}, ErrInvalidNickname
	}
	key, err := normalizeMAC(mac)
	if err != nil {
		return Config{}, err
	}
	return s.update(func(config *Config) error {
		config.Nicknames[key] = nickname
		return nil
	})
}

func (s *Store) RemoveNickname(mac net.HardwareAddr) (Config, error) {
	key, err := normalizeMAC(mac)
	if err != nil {
		return Config{}, err
	}
	return s.update(func(config *Config) error {
		delete(config.Nicknames, key)
		return nil
	})
}

func (s *Store) update(change func(*Config) error) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := lockFile(s.path + ".lock")
	if err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrLock, err)
	}
	defer unlock()
	config, err := s.load()
	if err != nil {
		return Config{}, err
	}
	if err := change(&config); err != nil {
		return Config{}, err
	}
	if err := s.save(config); err != nil {
		return Config{}, err
	}
	return clone(config), nil
}

func (s *Store) load() (Config, error) {
	file, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return defaultConfig(), nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("open configuration: %w", err)
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("%w: decode %q: %v", ErrCorrupt, s.path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return Config{}, fmt.Errorf("%w: decode %q: %v", ErrCorrupt, s.path, err)
	}
	if config.Version > CurrentVersion || config.Version < 1 {
		return Config{}, fmt.Errorf("%w: got %d, support through %d", ErrUnsupportedVersion, config.Version, CurrentVersion)
	}
	for config.Version < CurrentVersion {
		if err := migrate(&config); err != nil {
			return Config{}, err
		}
	}
	if config.Nicknames == nil {
		config.Nicknames = make(map[string]string)
	}
	if config.GatewayMAC != "" {
		mac, err := net.ParseMAC(config.GatewayMAC)
		if err != nil || len(mac) != 6 {
			return Config{}, fmt.Errorf("%w: invalid gateway_mac", ErrCorrupt)
		}
		config.GatewayMAC = strings.ToLower(mac.String())
	}
	if err := validateMonitoringSettings(config.MonitoringSettings()); err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	presets, err := normalizePresets(config.Presets)
	if err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	config.Presets = presets
	schedules, err := normalizeSchedules(config.Schedules, presets, false)
	if err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	config.Schedules = schedules
	blocks, err := normalizeDomainBlocks(config.DomainBlocks)
	if err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	config.DomainBlocks = blocks
	// A malformed authorization record must never brick the configuration:
	// it is dropped instead, which simply asks the operator to authorize
	// the gateway again.
	if config.GatewayAuth != nil {
		normalized, authErr := normalizeGatewayAuth(config.GatewayAuth)
		if authErr != nil {
			config.GatewayAuth = nil
		} else {
			config.GatewayAuth = normalized
		}
	}
	return clone(config), nil
}

func (config Config) MonitoringSettings() MonitoringSettings {
	return MonitoringSettings{
		ScanIntervalSeconds: config.ScanIntervalSeconds, OfflineAfterSeconds: config.OfflineAfterSeconds,
		HistoryRetentionDays: config.HistoryRetentionDays, AutoStart: config.AutoStart,
		PeriodicDiscovery: config.PeriodicDiscovery,
	}
}

func (config Config) NotificationSettings() NotificationSettings {
	return NotificationSettings{
		Enabled: config.NotificationsEnabled, NewDevices: config.NotifyNewDevices,
		KnownDevices: config.NotifyKnownDevices, DeviceOffline: config.NotifyDeviceOffline,
		SuspiciousDevices: config.NotifySuspicious,
	}
}

func validateMonitoringSettings(settings MonitoringSettings) error {
	if settings.ScanIntervalSeconds < 5 || settings.ScanIntervalSeconds > 3600 {
		return errors.New("scan interval must be between 5 and 3600 seconds")
	}
	if settings.OfflineAfterSeconds < 30 || settings.OfflineAfterSeconds > 86400 {
		return errors.New("offline timeout must be between 30 and 86400 seconds")
	}
	if settings.HistoryRetentionDays < 1 || settings.HistoryRetentionDays > 3650 {
		return errors.New("history retention must be between 1 and 3650 days")
	}
	return nil
}

func migrate(config *Config) error {
	switch config.Version {
	case 1:
		// Version 2 formalizes the optional gateway baseline and retains all
		// version-1 fields without changing their meaning.
		config.Version = 2
		return nil
	case 2:
		config.ScanIntervalSeconds = DefaultScanIntervalSeconds
		config.OfflineAfterSeconds = DefaultOfflineAfterSeconds
		config.HistoryRetentionDays = DefaultHistoryRetentionDays
		config.PeriodicDiscovery = true
		config.Version = 3
		return nil
	case 3:
		config.NotificationsEnabled = true
		config.NotifyNewDevices = true
		config.NotifyKnownDevices = true
		config.NotifyDeviceOffline = false
		config.NotifySuspicious = true
		config.Version = 4
		return nil
	case 4:
		// Version 5 introduces optional device automation: named presets,
		// recurring schedules, and per-device domain block lists. Everything is
		// optional, so a version-4 configuration simply gains empty defaults.
		config.Presets = nil
		config.Schedules = nil
		config.DomainBlocks = nil
		config.Version = 5
		return nil
	case 5:
		// Version 6 introduces the gateway authorization record. Existing
		// configurations gain no record, so the operator authorizes the
		// gateway once on the next launch.
		config.GatewayAuth = nil
		config.Version = 6
		return nil
	default:
		return fmt.Errorf("%w: no migration from version %d", ErrUnsupportedVersion, config.Version)
	}
}

func (s *Store) save(config Config) error {
	config.Version = CurrentVersion
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create configuration directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary configuration: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("protect temporary configuration: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		temporary.Close()
		return fmt.Errorf("encode configuration: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync configuration: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close configuration: %w", err)
	}
	if err := replaceFile(temporaryPath, s.path); err != nil {
		return fmt.Errorf("replace configuration: %w", err)
	}
	return nil
}

func defaultConfig() Config {
	return Config{
		Version: CurrentVersion, Nicknames: make(map[string]string),
		ScanIntervalSeconds:  DefaultScanIntervalSeconds,
		OfflineAfterSeconds:  DefaultOfflineAfterSeconds,
		HistoryRetentionDays: DefaultHistoryRetentionDays,
		PeriodicDiscovery:    true,
		NotificationsEnabled: true,
		NotifyNewDevices:     true,
		NotifyKnownDevices:   true,
		NotifyDeviceOffline:  false,
		NotifySuspicious:     true,
	}
}

func clone(config Config) Config {
	result := config
	result.Nicknames = make(map[string]string, len(config.Nicknames))
	for mac, nickname := range config.Nicknames {
		result.Nicknames[mac] = nickname
	}
	result.Presets = clonePresets(config.Presets)
	result.Schedules = cloneSchedules(config.Schedules)
	result.DomainBlocks = cloneDomainBlocks(config.DomainBlocks)
	if config.GatewayAuth != nil {
		record := *config.GatewayAuth
		result.GatewayAuth = &record
	}
	return result
}

func normalizeMAC(mac net.HardwareAddr) (string, error) {
	if len(mac) != 6 {
		return "", fmt.Errorf("expected a 6-byte MAC address, got %d bytes", len(mac))
	}
	return strings.ToLower(mac.String()), nil
}
