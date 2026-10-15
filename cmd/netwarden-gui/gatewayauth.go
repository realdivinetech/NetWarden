package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	appconfig "github.com/amdzy/NetWarden/internal/config"
	"github.com/amdzy/NetWarden/internal/gatewayauth"
	networkgateway "github.com/amdzy/NetWarden/internal/network/gateway"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// errAuthorizationRequired is returned by every privileged entry point while
// the gateway authorization gate is closed.
var errAuthorizationRequired = errors.New("the router must be authorized before NetWarden can operate")

// GatewayStatusDTO describes the authorization gate to the frontend: what the
// gate itself needs (gateway identity, available adapters) plus the current
// session state.
type GatewayStatusDTO struct {
	Authorized       bool       `json:"authorized"`
	Verified         bool       `json:"verified"`
	GatewayIP        string     `json:"gatewayIP"`
	GatewayMAC       string     `json:"gatewayMAC"`
	AuthorizedAt     *time.Time `json:"authorizedAt,omitempty"`
	Strategy         string     `json:"strategy,omitempty"`
	UsernameRequired bool       `json:"usernameRequired"`
	Adapters         []string   `json:"adapters"`
	Error            string     `json:"error,omitempty"`
}

// GatewayStatus reports the current authorization state without contacting the
// router, so the gate renders instantly on every launch.
func (a *GUIApp) GatewayStatus() GatewayStatusDTO {
	status := GatewayStatusDTO{Adapters: gatewayauth.AdapterNames()}
	a.authMu.RLock()
	status.Authorized = a.authorized
	status.Verified = a.authVerified
	a.authMu.RUnlock()
	_, config, err := loadSettings()
	if err != nil {
		status.Error = err.Error()
		return status
	}
	if record := config.GatewayAuth; record != nil {
		authorizedAt := record.AuthorizedAt
		status.AuthorizedAt = &authorizedAt
		status.Strategy = record.Strategy
		status.GatewayIP = record.GatewayIP
		status.GatewayMAC = record.GatewayMAC
	}
	if route, discoverErr := discoverGateway(); discoverErr == nil {
		status.GatewayIP = route.GatewayIP.String()
		if status.GatewayMAC == "" {
			status.GatewayMAC = config.GatewayMAC
		}
	}
	return status
}

// AuthorizeGateway offers the operator's gateway credentials to the router
// exactly once per click. On success it stores a password-free authorization
// record and opens the privileged session; ErrNoAdapter gateways are accepted
// with an unverified badge, while a rejection from a matching adapter requires
// an explicit acceptUnverified.
func (a *GUIApp) AuthorizeGateway(username, password string, acceptUnverified bool) (GatewayStatusDTO, error) {
	credentials := gatewayauth.Credentials{Username: strings.TrimSpace(username), Password: password}
	if err := credentials.Valid(); err != nil {
		return GatewayStatusDTO{}, err
	}
	store, config, err := loadSettings()
	if err != nil {
		return GatewayStatusDTO{}, err
	}
	target, err := gatewayTarget(config)
	if err != nil {
		return GatewayStatusDTO{}, err
	}
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	fp, err := gatewayauth.Probe(ctx, target)
	if err != nil {
		return GatewayStatusDTO{}, fmt.Errorf("the router at %s could not be reached: %w", target.IP, err)
	}
	chain := gatewayauth.DefaultChain()
	status := GatewayStatusDTO{
		Adapters:         chain.AdapterNames(),
		UsernameRequired: chain.UsernameRequired(fp),
		GatewayIP:        target.IP,
		GatewayMAC:       target.MAC,
	}
	result, verifyErr := chain.Verify(ctx, target, fp, credentials)

	strategy := ""
	verified := false
	switch {
	case verifyErr == nil && result.Verified:
		strategy, verified = result.Strategy, true
	case errors.Is(verifyErr, gatewayauth.ErrNoAdapter):
		// Nothing on this gateway can check the password, so the typed
		// password becomes an unverified session rather than a dead end.
	case errors.Is(verifyErr, gatewayauth.ErrRejected):
		if !acceptUnverified {
			return GatewayStatusDTO{}, fmt.Errorf("%w — if you are certain the password is correct, tick “continue without verification”", verifyErr)
		}
	default:
		return GatewayStatusDTO{}, verifyErr
	}

	record, err := gatewayauth.NewRecord(target, strategy, verified, time.Now())
	if err != nil {
		return GatewayStatusDTO{}, fmt.Errorf("could not seal the authorization record: %w", err)
	}
	if _, err := store.SetGatewayAuth(&record); err != nil {
		return GatewayStatusDTO{}, fmt.Errorf("could not store the authorization record: %w", err)
	}
	a.beginAuthorizedSession(verified)
	a.startAuthorizedServices(config)
	a.emitGatewayChanged()

	status.Authorized = true
	status.Verified = verified
	status.Strategy = strategy
	return status, nil
}

// GatewayForget clears the stored authorization and closes the gate, stopping
// the privileged session if one is running.
func (a *GUIApp) GatewayForget() (GatewayStatusDTO, error) {
	store, _, err := loadSettings()
	if err != nil {
		return GatewayStatusDTO{}, err
	}
	if _, err := store.SetGatewayAuth(nil); err != nil {
		return GatewayStatusDTO{}, err
	}
	a.lockSession()
	return a.GatewayStatus(), nil
}

// requireAuthorized is the single choke point every privileged operation
// passes through. It re-derives the stored proof against the gateway that is
// reachable right now, so a network change relocks the gate immediately.
func (a *GUIApp) requireAuthorized() error {
	a.authMu.RLock()
	authorized := a.authorized
	a.authMu.RUnlock()
	if !authorized {
		return errAuthorizationRequired
	}
	_, config, err := loadSettings()
	if err == nil && config.GatewayAuth != nil {
		if target, targetErr := gatewayTarget(config); targetErr == nil {
			if gatewayauth.Matches(config.GatewayAuth, target) && gatewayauth.CheckProof(config.GatewayAuth, target) {
				return nil
			}
		}
	}
	a.lockSession()
	return fmt.Errorf("%w: the gateway identity changed, so the session was locked", errAuthorizationRequired)
}

// applyStoredAuthorization validates the persisted record against the gateway
// on this network and opens the session when it holds.
func (a *GUIApp) applyStoredAuthorization(config appconfig.Config) bool {
	if config.GatewayAuth == nil {
		return false
	}
	target, err := gatewayTarget(config)
	if err != nil {
		a.log(slog.LevelInfo, "gateway not resolvable for stored authorization", "component", "lifecycle", "error", err)
		return false
	}
	if !gatewayauth.Matches(config.GatewayAuth, target) || !gatewayauth.CheckProof(config.GatewayAuth, target) {
		return false
	}
	a.beginAuthorizedSession(config.GatewayAuth.Verified)
	return true
}

// beginAuthorizedSession marks the in-memory session open.
func (a *GUIApp) beginAuthorizedSession(verified bool) {
	a.authMu.Lock()
	a.authorized = true
	a.authVerified = verified
	a.authMu.Unlock()
}

// lockSession closes the in-memory session, stops any running capture, and
// notifies the frontend so the gate can reappear without a reload.
func (a *GUIApp) lockSession() {
	a.authMu.Lock()
	changed := a.authorized
	a.authorized = false
	a.authVerified = false
	a.authMu.Unlock()
	if !changed {
		return
	}
	a.log(slog.LevelInfo, "gateway authorization lost", "component", "lifecycle")
	_ = a.StopMonitoring()
	a.emitGatewayChanged()
}

// startAuthorizedServices launches everything held behind the gate — the
// schedule engine and the automatic capture session — exactly once.
func (a *GUIApp) startAuthorizedServices(config appconfig.Config) {
	a.authMu.Lock()
	if a.servicesStarted {
		a.authMu.Unlock()
		return
	}
	a.servicesStarted = true
	a.authMu.Unlock()

	a.startScheduleEngine(a.ctx)
	if !config.AutoStart || config.Interface == "" {
		return
	}
	go func() {
		if err := a.StartMonitoring(config.Interface); err != nil {
			a.recordActivity(ActivityDTO{At: time.Now().UTC(), Kind: "error", Severity: "error", Title: "Automatic monitoring failed", Detail: err.Error()})
			runtime.EventsEmit(a.ctx, "runtime:error", err.Error())
		}
	}()
}

// emitGatewayChanged tells the frontend that the gate state moved in either
// direction (opened by AuthorizeGateway, closed by lockSession).
func (a *GUIApp) emitGatewayChanged() {
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "gateway:changed")
	}
}

func discoverGateway() (networkgateway.Route, error) {
	return (networkgateway.SystemDiscoverer{}).Discover(context.Background())
}

// gatewayTarget resolves the gateway identity the authorization record binds
// to: the default route's gateway plus the configured hardware address.
func gatewayTarget(config appconfig.Config) (gatewayauth.Target, error) {
	route, err := discoverGateway()
	if err != nil {
		return gatewayauth.Target{}, fmt.Errorf("the default gateway could not be determined: %w", err)
	}
	if !route.GatewayIP.IsValid() || route.GatewayIP.IsUnspecified() {
		return gatewayauth.Target{}, errors.New("this network has no default gateway")
	}
	return gatewayauth.Target{
		IP:      route.GatewayIP.Unmap().String(),
		LocalIP: route.InterfaceIP.Unmap().String(),
		MAC:     config.GatewayMAC,
	}, nil
}
