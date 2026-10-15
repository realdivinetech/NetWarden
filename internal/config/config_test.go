package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestStorePersistsInterfaceAndNickname(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	store := NewStore(path)
	if _, err := store.SetInterface("en0"); err != nil {
		t.Fatal(err)
	}
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	gatewayMAC, _ := net.ParseMAC("00:00:0c:00:00:01")
	if _, err := store.SetGatewayMAC(gatewayMAC); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetNickname(mac, "Living Room TV"); err != nil {
		t.Fatal(err)
	}

	got, err := NewStore(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != CurrentVersion || got.Interface != "en0" || got.GatewayMAC != gatewayMAC.String() || got.Nicknames["02:00:00:00:00:01"] != "Living Room TV" {
		t.Fatalf("unexpected configuration: %#v", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows reports synthesized POSIX permission bits; access is governed
	// by the file's ACL instead of chmod-style mode bits.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("configuration permissions are too broad: %o", info.Mode().Perm())
	}
}

func TestStoreReportsCorruptConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(path).Load(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want ErrCorrupt", err)
	}
}

func TestStoreRejectsTrailingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"version":1} {"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(path).Load(); err == nil {
		t.Fatal("expected trailing JSON error")
	}
}

func TestStoreRejectsFutureVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"version":999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewStore(path).Load()
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("got %v, want ErrUnsupportedVersion", err)
	}
}

func TestStoreMigratesVersionOneConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"interface":"en0","nicknames":{"02:00:00:00:00:01":"Printer"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := NewStore(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	if config.Version != CurrentVersion || config.Interface != "en0" || config.Nicknames["02:00:00:00:00:01"] != "Printer" {
		t.Fatalf("unexpected migrated config: %#v", config)
	}
	if config.ScanIntervalSeconds != DefaultScanIntervalSeconds || !config.PeriodicDiscovery {
		t.Fatalf("monitoring defaults were not migrated: %#v", config)
	}
}

func TestStorePersistsMonitoringSettings(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "config.json"))
	want := MonitoringSettings{ScanIntervalSeconds: 30, OfflineAfterSeconds: 120, HistoryRetentionDays: 180, AutoStart: true, PeriodicDiscovery: false}
	if _, err := store.SetMonitoringSettings(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.MonitoringSettings() != want {
		t.Fatalf("got %#v, want %#v", got.MonitoringSettings(), want)
	}
}

func TestStorePersistsNotificationSettings(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "config.json"))
	want := NotificationSettings{Enabled: true, NewDevices: false, KnownDevices: true, DeviceOffline: true, SuspiciousDevices: false}
	if _, err := store.SetNotificationSettings(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.NotificationSettings() != want {
		t.Fatalf("got %#v, want %#v", got.NotificationSettings(), want)
	}
}

func TestStoreRejectsInvalidMonitoringSettings(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "config.json"))
	_, err := store.SetMonitoringSettings(MonitoringSettings{ScanIntervalSeconds: 1, OfflineAfterSeconds: 60, HistoryRetentionDays: 90})
	if err == nil {
		t.Fatal("expected invalid scan interval error")
	}
}

func TestSetNicknameValidatesInput(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "config.json"))
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	if _, err := store.SetNickname(mac, "  "); !errors.Is(err, ErrInvalidNickname) {
		t.Fatalf("got %v, want ErrInvalidNickname", err)
	}
}

func TestSeparateStoresDoNotLoseConcurrentUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	const count = 16
	var wait sync.WaitGroup
	errorsFound := make(chan error, count)
	for i := 0; i < count; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			mac, _ := net.ParseMAC(fmt.Sprintf("02:00:00:00:00:%02x", index))
			_, err := NewStore(path).SetNickname(mac, fmt.Sprintf("Device %d", index))
			errorsFound <- err
		}(i)
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	config, err := NewStore(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Nicknames) != count {
		t.Fatalf("got %d nicknames, want %d", len(config.Nicknames), count)
	}
}

func TestStoreMigratesVersionFourConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"version":4,"interface":"en0","scan_interval_seconds":10,"offline_after_seconds":60,"history_retention_days":90}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := NewStore(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	if config.Version != CurrentVersion || config.Interface != "en0" {
		t.Fatalf("unexpected migrated config: %#v", config)
	}
	if len(config.Presets) != 0 || len(config.Schedules) != 0 || len(config.DomainBlocks) != 0 {
		t.Fatalf("version 5 automation fields should default to empty: %#v", config)
	}
}

func TestStorePersistsPresetsAndSchedules(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "config.json"))
	presets := []Preset{
		{ID: "night", Name: "Night", Action: PresetActionDisconnect},
		{ID: "cap", Name: "Cap", Action: PresetActionLimit, DownloadBitsPerSecond: 8_000_000, UploadBitsPerSecond: 2_000_000},
		{ID: "social", Name: "Social", Action: PresetActionBlock, Domains: []string{"Example.COM", "cdn.example.com"}},
	}
	if _, err := store.SetPresets(presets); err != nil {
		t.Fatal(err)
	}
	schedules := []Schedule{
		{ID: "bed", Name: "Bedtime", Enabled: true, Days: []int{0, 1, 2}, Start: "22:00", End: "07:00", PresetID: "night", MACs: []string{"02:00:00:00:00:01"}},
	}
	if _, err := store.SetSchedules(schedules); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Presets) != 3 || got.Presets[2].Domains[0] != "example.com" {
		t.Fatalf("unexpected presets: %#v", got.Presets)
	}
	if len(got.Schedules) != 1 || got.Schedules[0].PresetID != "night" || got.Schedules[0].MACs[0] != "02:00:00:00:00:01" {
		t.Fatalf("unexpected schedules: %#v", got.Schedules)
	}
}

func TestStorePrunesSchedulesWhenPresetRemoved(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "config.json"))
	if _, err := store.SetPresets([]Preset{{ID: "night", Name: "Night", Action: PresetActionDisconnect}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetSchedules([]Schedule{{ID: "bed", Name: "Bedtime", Enabled: true, Days: []int{1}, Start: "22:00", End: "07:00", PresetID: "night", MACs: []string{"02:00:00:00:00:01"}}}); err != nil {
		t.Fatal(err)
	}
	got, err := store.SetPresets(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Schedules) != 0 {
		t.Fatalf("schedules referencing a removed preset should be pruned: %#v", got.Schedules)
	}
}

func TestStorePersistsDomainBlocks(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "config.json"))
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	if _, err := store.SetDomainBlocks(mac, []string{"YouTube.com", "youtube.com"}); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if domains := got.BlockedDomains(mac); len(domains) != 1 || domains[0] != "youtube.com" {
		t.Fatalf("unexpected domain blocks: %#v", got.DomainBlocks)
	}
	if _, err := store.RemoveDomainBlocks(mac); err != nil {
		t.Fatal(err)
	}
	got, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.BlockedDomains(mac)) != 0 {
		t.Fatalf("domain blocks were not removed: %#v", got.DomainBlocks)
	}
}

func TestStoreRejectsInvalidPresets(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "config.json"))
	if _, err := store.SetPresets([]Preset{{ID: "x", Name: "X", Action: PresetActionLimit}}); !errors.Is(err, ErrInvalidPreset) {
		t.Fatalf("got %v, want ErrInvalidPreset for a rate-less limit preset", err)
	}
	if _, err := store.SetPresets([]Preset{{ID: "x", Name: "X", Action: PresetActionBlock, Domains: []string{"bad domain"}}}); !errors.Is(err, ErrInvalidDomainBlock) {
		t.Fatalf("got %v, want ErrInvalidDomainBlock", err)
	}
	if _, err := store.SetPresets([]Preset{{ID: "x", Name: "X", Action: "launch"}}); !errors.Is(err, ErrInvalidPreset) {
		t.Fatalf("got %v, want ErrInvalidPreset for an unsupported action", err)
	}
}

func TestStoreRejectsInvalidSchedules(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "config.json"))
	if _, err := store.SetPresets([]Preset{{ID: "night", Name: "Night", Action: PresetActionDisconnect}}); err != nil {
		t.Fatal(err)
	}
	cases := []Schedule{
		{ID: "s", Name: "S", Enabled: true, Days: []int{1}, Start: "25:00", End: "07:00", PresetID: "night", MACs: []string{"02:00:00:00:00:01"}},
		{ID: "s", Name: "S", Enabled: true, Days: []int{9}, Start: "22:00", End: "07:00", PresetID: "night", MACs: []string{"02:00:00:00:00:01"}},
		{ID: "s", Name: "S", Enabled: true, Days: []int{1}, Start: "22:00", End: "22:00", PresetID: "night", MACs: []string{"02:00:00:00:00:01"}},
		{ID: "s", Name: "S", Enabled: true, Days: []int{1}, Start: "22:00", End: "07:00", PresetID: "night", MACs: []string{"not-a-mac"}},
		{ID: "s", Name: "S", Enabled: true, Days: []int{1}, Start: "22:00", End: "07:00", PresetID: "missing", MACs: []string{"02:00:00:00:00:01"}},
	}
	for _, schedule := range cases {
		if _, err := store.SetSchedules([]Schedule{schedule}); !errors.Is(err, ErrInvalidSchedule) {
			t.Fatalf("schedule %#v: got %v, want ErrInvalidSchedule", schedule, err)
		}
	}
}

func TestStoreMigratesVersionFiveConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	payload := `{"version":5,"interface":"en0","scan_interval_seconds":10,"offline_after_seconds":60,"history_retention_days":90,"periodic_discovery":true}`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := NewStore(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	if config.Version != CurrentVersion || config.Interface != "en0" {
		t.Fatalf("unexpected migrated config: %#v", config)
	}
	if config.GatewayAuth != nil {
		t.Fatalf("version 6 adds no authorization record by default: %#v", config.GatewayAuth)
	}
}

func TestStorePersistsGatewayAuthorization(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "config.json"))
	record := &GatewayAuthRecord{
		AuthorizedAt: time.Now().UTC(),
		GatewayIP:    "192.168.100.1",
		LocalIP:      "192.168.100.7",
		GatewayMAC:   "DC:EC:9A:C9:CA:E0",
		Strategy:     "huawei-ont",
		Verified:     true,
		Secret:       "c2VjcmV0",
		Proof:        "cHJvb2Y=",
	}
	if _, err := store.SetGatewayAuth(record); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.GatewayAuth == nil || !got.GatewayAuth.Verified || got.GatewayAuth.GatewayMAC != "dc:ec:9a:c9:ca:e0" {
		t.Fatalf("authorization record did not round-trip: %#v", got.GatewayAuth)
	}
	if _, err := store.SetGatewayAuth(nil); err != nil {
		t.Fatal(err)
	}
	got, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.GatewayAuth != nil {
		t.Fatalf("clearing the record should force the gate again: %#v", got.GatewayAuth)
	}
}

func TestStoreRejectsIncompleteGatewayAuthorization(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "config.json"))
	if _, err := store.SetGatewayAuth(&GatewayAuthRecord{GatewayIP: "192.168.1.1"}); err == nil {
		t.Fatal("expected an incomplete authorization record to be rejected")
	}
	if _, err := store.SetGatewayAuth(&GatewayAuthRecord{GatewayIP: "not-an-ip", Secret: "c2VjcmV0", Proof: "cHJvb2Y="}); err == nil {
		t.Fatal("expected an invalid gateway address to be rejected")
	}
}

func TestStoreDropsMalformedGatewayAuthorizationOnLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	payload := `{"version":6,"gateway_auth":{"authorized_at":"2026-01-01T00:00:00Z","gateway_ip":"","strategy":"x","verified":true,"secret":"","proof":""},"scan_interval_seconds":10,"offline_after_seconds":60,"history_retention_days":90}`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := NewStore(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	if config.GatewayAuth != nil {
		t.Fatalf("a malformed record must be dropped, not crash the load: %#v", config.GatewayAuth)
	}
}
