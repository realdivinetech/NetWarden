package gatewayauth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// jsBase64 mirrors what router login scripts do when they call btoa() on the
// password: every character contributes its low byte, then standard base64.
func jsBase64(value string) string {
	raw := make([]byte, 0, len(value))
	for _, character := range value {
		raw = append(raw, byte(character))
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// postForm submits an application/x-www-form-urlencoded body to the gateway.
// The response body is returned bounded and fully read.
func postForm(ctx context.Context, client *http.Client, endpoint string, values url.Values, headers map[string]string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return doRequest(ctx, client, req)
}

// postJSON submits a JSON body to the gateway and returns the parsed reply.
func postJSON(ctx context.Context, client *http.Client, endpoint, body string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return doRequest(ctx, client, req)
}

// formResult classifies a gateway's answer to a form login.
type formResult int

const (
	formUnrecognized formResult = iota
	formAccepted
	formRefused
)

// classifyFormResponse decides whether a login reply proves success. Rejection
// markers take priority so an error page can never read as acceptance.
func classifyFormResponse(status int, body []byte, finalPath string, rejectionMarkers, acceptanceMarkers []string) formResult {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return formRefused
	}
	text := string(body)
	for _, marker := range rejectionMarkers {
		if pageContains(text, marker) {
			return formRefused
		}
	}
	if strings.Contains(strings.ToLower(finalPath), "login.asp") {
		return formRefused
	}
	if status >= 400 {
		return formRefused
	}
	for _, marker := range acceptanceMarkers {
		if pageContains(text, marker) {
			return formAccepted
		}
	}
	if len(strings.TrimSpace(text)) == 0 && status < 400 {
		return formUnrecognized
	}
	if status >= 200 && status < 400 {
		return formUnrecognized
	}
	return formUnrecognized
}

// describeStatus renders an HTTP status for an error message.
func describeStatus(status int) string { return fmt.Sprintf("status %d", status) }
