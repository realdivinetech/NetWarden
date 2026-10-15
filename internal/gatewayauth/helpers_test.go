package gatewayauth

import (
	"net"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// serverTarget turns an httptest server URL into a pinned Target.
func serverTarget(t *testing.T, server *httptest.Server) Target {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	return Target{IP: host, Port: port}
}

// probeFingerprint probes the test server and fails the test when unreachable.
func probeFingerprint(t *testing.T, target Target) Fingerprint {
	t.Helper()
	fp, err := Probe(t.Context(), target)
	if err != nil {
		t.Fatalf("probe gateway: %v", err)
	}
	return fp
}

// credentials is a shorthand for a complete login.
func credentials() Credentials {
	return Credentials{Username: "admin", Password: "correct horse"}
}

// containsDetail reports whether an error chain carries the marker.
func containsDetail(err error, marker string) bool {
	return err != nil && strings.Contains(err.Error(), marker)
}
