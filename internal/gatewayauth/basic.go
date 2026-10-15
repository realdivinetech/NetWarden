package gatewayauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// BasicVerifier handles gateways that answer with an RFC 7617 Basic
// challenge. This covers a large share of enthusiast and enterprise gear,
// including most NETGEAR consumer routers.
type BasicVerifier struct{}

// Name implements Verifier.
func (v *BasicVerifier) Name() string { return "http-basic" }

// UsernameRequired implements Verifier.
func (v *BasicVerifier) UsernameRequired() bool { return true }

// Match implements Verifier.
func (v *BasicVerifier) Match(fp Fingerprint) bool {
	return challengeHasScheme(fp.Challenge(), "basic")
}

// Verify implements Verifier. It performs exactly one authenticated request;
// a wrong password yields 401 and is reported as a rejection.
func (v *BasicVerifier) Verify(ctx context.Context, target Target, fp Fingerprint, creds Credentials) (Result, error) {
	client := newPinnedClient(target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gatewayURL(fp.Scheme, target, "/"), nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.SetBasicAuth(creds.Username, creds.Password)
	resp, _, err := doRequest(ctx, client, req)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	if resp.Body != nil {
		resp.Body.Close()
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return Result{}, fmt.Errorf("credentials refused with status %d", resp.StatusCode)
	case resp.StatusCode >= 400:
		return Result{}, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return Result{Verified: true, Strategy: v.Name()}, nil
}

// challengeHasScheme reports whether a WWW-Authenticate header carries the
// given scheme, ignoring other challenges that may share the header.
func challengeHasScheme(header, scheme string) bool {
	for _, part := range strings.Split(header, ",") {
		token := strings.TrimSpace(part)
		if cut := strings.IndexAny(token, " \t"); cut >= 0 {
			token = token[:cut]
		}
		if strings.EqualFold(token, scheme) {
			return true
		}
	}
	return false
}
