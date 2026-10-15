package main

import (
	"context"
	"net"
	"strings"
	"time"

	appconfig "github.com/amdzy/NetWarden/internal/config"
)

// Schedules returns the configured recurring device action windows.
func (a *GUIApp) Schedules() ([]appconfig.Schedule, error) {
	_, config, err := loadSettings()
	if err != nil {
		return nil, err
	}
	return config.ScheduleList(), nil
}

// SaveSchedules replaces the schedule list and returns the normalized result.
func (a *GUIApp) SaveSchedules(schedules []appconfig.Schedule) ([]appconfig.Schedule, error) {
	store, _, err := loadSettings()
	if err != nil {
		return nil, err
	}
	updated, err := store.SetSchedules(schedules)
	if err != nil {
		return nil, err
	}
	return updated.ScheduleList(), nil
}

// scheduleState records what the engine applied to a device so the window can
// be unwound without discarding a user's pre-existing block list.
type scheduleState struct {
	presetID        string
	action          string
	previousDomains []string
}

// scheduleEngine applies enabled schedule presets while their weekly window is
// open and releases them when it closes. It runs inside the GUI process while
// monitoring is active and is owned by a single goroutine.
type scheduleEngine struct {
	app     *GUIApp
	applied map[string]scheduleState
}

func (a *GUIApp) startScheduleEngine(ctx context.Context) {
	engine := &scheduleEngine{app: a, applied: make(map[string]scheduleState)}
	a.scheduleMu.Lock()
	a.scheduleEngine = engine
	a.scheduleMu.Unlock()
	go engine.run(ctx)
}

func (e *scheduleEngine) run(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	e.reconcile()
	for {
		select {
		case <-ctx.Done():
			e.releaseAll()
			return
		case <-ticker.C:
			e.reconcile()
		}
	}
}

func (e *scheduleEngine) reconcile() {
	if _, err := e.app.activeRuntime(); err != nil {
		return
	}
	_, config, err := loadSettings()
	if err != nil {
		return
	}
	presets := make(map[string]appconfig.Preset)
	for _, preset := range config.PresetList() {
		presets[preset.ID] = preset
	}
	now := time.Now()
	desired := make(map[string]string)
	for _, schedule := range config.ScheduleList() {
		if !schedule.Enabled || !scheduleActive(schedule, now) {
			continue
		}
		for _, mac := range schedule.MACs {
			desired[mac] = schedule.PresetID
		}
	}
	for mac, state := range e.applied {
		if desired[mac] == state.presetID {
			continue
		}
		e.release(mac, state)
	}
	for mac, presetID := range desired {
		preset, ok := presets[presetID]
		if !ok {
			continue
		}
		if state, exists := e.applied[mac]; exists {
			if state.presetID == presetID {
				continue
			}
			e.release(mac, state)
		}
		e.apply(mac, preset)
	}
}

func (e *scheduleEngine) apply(mac string, preset appconfig.Preset) {
	ipText, ok := e.deviceIP(mac)
	if !ok {
		return
	}
	state := scheduleState{presetID: preset.ID, action: preset.Action}
	if preset.Action == appconfig.PresetActionBlock {
		if _, config, err := loadSettings(); err == nil {
			if parsed, parseErr := net.ParseMAC(mac); parseErr == nil {
				state.previousDomains = config.BlockedDomains(parsed)
			}
		}
	}
	var err error
	switch preset.Action {
	case appconfig.PresetActionDisconnect:
		err = e.app.DisconnectDevice(ipText, mac)
	case appconfig.PresetActionLimit:
		err = e.app.SetBandwidthLimit(ipText, mac, uint64(preset.DownloadBitsPerSecond), uint64(preset.UploadBitsPerSecond), 0)
	case appconfig.PresetActionBlock:
		err = e.app.SetDomainBlock(ipText, mac, preset.Domains)
	default:
		return
	}
	if err != nil {
		e.app.recordActivity(ActivityDTO{At: time.Now().UTC(), Kind: "schedule", Severity: "error",
			Title: "Schedule preset failed", Detail: preset.Name + " · " + mac + " · " + err.Error()})
		return
	}
	e.applied[mac] = state
	e.app.recordActivity(ActivityDTO{At: time.Now().UTC(), Kind: "schedule", Severity: "info",
		Title: "Schedule applied", Detail: preset.Name + " · " + mac})
}

func (e *scheduleEngine) release(mac string, state scheduleState) {
	ipText, _ := e.deviceIP(mac)
	switch state.action {
	case appconfig.PresetActionDisconnect:
		_ = e.app.RestoreControl(ipText, mac)
	case appconfig.PresetActionLimit:
		_ = e.app.RemoveBandwidthLimit(mac)
	case appconfig.PresetActionBlock:
		if len(state.previousDomains) > 0 {
			_ = e.app.SetDomainBlock(ipText, mac, state.previousDomains)
		} else {
			_ = e.app.RemoveDomainBlock(mac)
		}
	}
	delete(e.applied, mac)
	e.app.recordActivity(ActivityDTO{At: time.Now().UTC(), Kind: "schedule", Severity: "info",
		Title: "Schedule released", Detail: mac})
}

func (e *scheduleEngine) releaseAll() {
	for mac, state := range e.applied {
		e.release(mac, state)
	}
}

func (e *scheduleEngine) deviceIP(mac string) (string, bool) {
	devices, err := e.app.Devices()
	if err != nil {
		return "", false
	}
	for _, current := range devices {
		if strings.EqualFold(current.MAC, mac) {
			return current.IP, true
		}
	}
	return "", false
}

// scheduleActive reports whether a weekly window is open at the given instant.
// A window whose end is not after its start wraps past midnight into the next
// day.
func scheduleActive(schedule appconfig.Schedule, now time.Time) bool {
	start, ok := clockMinutes(schedule.Start)
	if !ok {
		return false
	}
	end, ok := clockMinutes(schedule.End)
	if !ok || start == end {
		return false
	}
	minutes := now.Hour()*60 + now.Minute()
	weekday := int(now.Weekday())
	if start < end {
		return containsDay(schedule.Days, weekday) && minutes >= start && minutes < end
	}
	if containsDay(schedule.Days, weekday) && minutes >= start {
		return true
	}
	return containsDay(schedule.Days, (weekday+6)%7) && minutes < end
}

func clockMinutes(value string) (int, bool) {
	parsed, err := time.Parse("15:04", value)
	if err != nil {
		return 0, false
	}
	return parsed.Hour()*60 + parsed.Minute(), true
}

func containsDay(days []int, day int) bool {
	for _, candidate := range days {
		if candidate == day {
			return true
		}
	}
	return false
}
