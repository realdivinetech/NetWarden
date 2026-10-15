package gatewayauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Probe collects the gateway fingerprint used to choose a verifier. It only
// reads the public login page: no credentials are offered here, so a failed
// probe simply means the gateway is unreachable rather than rejected.
func Probe(ctx context.Context, target Target) (Fingerprint, error) {
	if target.IP == "" {
		return Fingerprint{}, fmt.Errorf("%w: no gateway address", ErrUnreachable)
	}
	var lastErr error
	for _, scheme := range []string{"http", "https"} {
		client := newPinnedClient(target)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, gatewayURL(scheme, target, "/"), nil)
		if err != nil {
			return Fingerprint{}, err
		}
		req.Header.Set("User-Agent", userAgent)
		resp, body, err := doRequest(ctx, client, req)
		if err != nil {
			lastErr = err
			continue
		}
		header := resp.Header.Clone()
		if resp.Body != nil {
			resp.Body.Close()
		}
		return Fingerprint{
			Reachable: true,
			Status:    resp.StatusCode,
			Scheme:    scheme,
			Header:    header,
			Body:      string(body),
		}, nil
	}
	return Fingerprint{}, fmt.Errorf("%w: %v", ErrUnreachable, lastErr)
}

// userAgent identifies the probe without pretending to be a browser.
const userAgent = "NetWarden-GatewayAuth/1.0"

// pageContains is a convenience for matching a response body case-insensitively.
func pageContains(body, marker string) bool {
	return strings.Contains(strings.ToLower(body), strings.ToLower(marker))
}
