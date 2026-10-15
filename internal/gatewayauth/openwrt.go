package gatewayauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// OpenWrtVerifier authenticates OpenWrt/LuCI gateways through the ubus session
// endpoint, falling back to the legacy LuCI JSON-RPC auth controller used by
// older releases.
type OpenWrtVerifier struct{}

// Name implements Verifier.
func (v *OpenWrtVerifier) Name() string { return "openwrt-luci" }

// UsernameRequired implements Verifier.
func (v *OpenWrtVerifier) UsernameRequired() bool { return true }

// Match implements Verifier.
func (v *OpenWrtVerifier) Match(fp Fingerprint) bool {
	return fp.BodyContainsAny("luci-static", "openwrt", "<title>luci", "luci_theme", "/www/luci")
}

// ubusUnauthenticated is the well-known all-zero ubus session id.
const ubusUnauthenticated = "00000000000000000000000000000000"

type ubusReply struct {
	Result []json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Verify implements Verifier with one ubus login, plus one legacy fallback
// when the modern endpoint does not exist.
func (v *OpenWrtVerifier) Verify(ctx context.Context, target Target, fp Fingerprint, creds Credentials) (Result, error) {
	client := newPinnedClient(target)
	scheme := fp.Scheme

	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "call",
		"params": []any{
			ubusUnauthenticated,
			"session",
			"login",
			map[string]string{"username": creds.Username, "password": creds.Password},
		},
	})
	if err != nil {
		return Result{}, err
	}

	resp, body, err := postJSON(ctx, client, gatewayURL(scheme, target, "/ubus"), string(payload))
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	if resp.Body != nil {
		resp.Body.Close()
	}
	if resp.StatusCode != http.StatusNotFound {
		verified, refusal, err := interpretUbusReply(resp.StatusCode, body)
		if err != nil {
			return Result{}, err
		}
		if verified {
			return Result{Verified: true, Strategy: v.Name()}, nil
		}
		if refusal != "" {
			return Result{}, fmt.Errorf("router rejected the credentials: %s", refusal)
		}
		return Result{}, fmt.Errorf("router rejected the credentials (%s)", describeStatus(resp.StatusCode))
	}

	// Older LuCI exposes the JSON-RPC auth controller instead.
	legacy, err := json.Marshal(map[string]any{
		"method": "login",
		"params": []any{creds.Username, creds.Password},
	})
	if err != nil {
		return Result{}, err
	}
	resp, body, err = postJSON(ctx, client, gatewayURL(scheme, target, "/cgi-bin/luci/rpc/auth"), string(legacy))
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	if resp.Body != nil {
		resp.Body.Close()
	}
	if resp.StatusCode >= 400 {
		return Result{}, fmt.Errorf("router rejected the credentials (%s)", describeStatus(resp.StatusCode))
	}
	var legacyReply struct {
		Result *string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &legacyReply); err != nil {
		return Result{}, fmt.Errorf("unrecognized reply from the router")
	}
	if legacyReply.Error != nil && legacyReply.Error.Message != "" {
		return Result{}, fmt.Errorf("router rejected the credentials: %s", legacyReply.Error.Message)
	}
	if legacyReply.Result == nil || *legacyReply.Result == "" || *legacyReply.Result == ubusUnauthenticated {
		return Result{}, fmt.Errorf("router rejected the credentials")
	}
	return Result{Verified: true, Strategy: v.Name()}, nil
}

// interpretUbusReply turns a /ubus response into acceptance or refusal.
func interpretUbusReply(status int, body []byte) (verified bool, refusal string, err error) {
	if status >= 400 {
		return false, "", nil
	}
	var reply ubusReply
	if err := json.Unmarshal(body, &reply); err != nil {
		return false, "", fmt.Errorf("unrecognized reply from the router")
	}
	if reply.Error != nil && reply.Error.Message != "" {
		return false, reply.Error.Message, nil
	}
	if len(reply.Result) < 2 {
		return false, "", nil
	}
	var code float64
	if err := json.Unmarshal(reply.Result[0], &code); err != nil {
		return false, "", fmt.Errorf("unrecognized reply from the router")
	}
	if code != 0 {
		var detail struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(reply.Result[1], &detail)
		if detail.Message == "" {
			detail.Message = fmt.Sprintf("status %.0f", code)
		}
		return false, detail.Message, nil
	}
	var session struct {
		ID string `json:"ubus_rpc_session"`
	}
	if err := json.Unmarshal(reply.Result[1], &session); err != nil {
		return false, "", fmt.Errorf("unrecognized reply from the router")
	}
	if session.ID == "" || session.ID == ubusUnauthenticated {
		return false, "invalid session", nil
	}
	return true, "", nil
}
