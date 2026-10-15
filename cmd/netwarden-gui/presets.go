package main

import (
	"fmt"

	appconfig "github.com/amdzy/NetWarden/internal/config"
)

// Presets returns the configured reusable device actions.
func (a *GUIApp) Presets() ([]appconfig.Preset, error) {
	_, config, err := loadSettings()
	if err != nil {
		return nil, err
	}
	return config.PresetList(), nil
}

// SavePresets replaces the preset list and returns the normalized result.
// Schedules referencing a removed preset are pruned.
func (a *GUIApp) SavePresets(presets []appconfig.Preset) ([]appconfig.Preset, error) {
	store, _, err := loadSettings()
	if err != nil {
		return nil, err
	}
	updated, err := store.SetPresets(presets)
	if err != nil {
		return nil, err
	}
	return updated.PresetList(), nil
}

// ApplyPreset runs a preset's action against a single device.
func (a *GUIApp) ApplyPreset(id, ipText, macText string) error {
	_, config, err := loadSettings()
	if err != nil {
		return err
	}
	var preset appconfig.Preset
	found := false
	for _, candidate := range config.PresetList() {
		if candidate.ID == id {
			preset, found = candidate, true
			break
		}
	}
	if !found {
		return fmt.Errorf("preset %q was not found", id)
	}
	switch preset.Action {
	case appconfig.PresetActionDisconnect:
		return a.DisconnectDevice(ipText, macText)
	case appconfig.PresetActionLimit:
		return a.SetBandwidthLimit(ipText, macText, uint64(preset.DownloadBitsPerSecond), uint64(preset.UploadBitsPerSecond), 0)
	case appconfig.PresetActionBlock:
		return a.SetDomainBlock(ipText, macText, preset.Domains)
	default:
		return fmt.Errorf("preset %q uses unsupported action %q", id, preset.Action)
	}
}
