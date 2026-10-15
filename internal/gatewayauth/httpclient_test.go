package gatewayauth

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPinnedClientIgnoresEnvironmentProxy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")

	target := serverTarget(t, server)
	client := newPinnedClient(target)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, gatewayURL("http", target, "/"), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, body, err := doRequest(t.Context(), client, req)
	if err != nil {
		t.Fatalf("request should bypass the environment proxy: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
}

func TestPinnedClientRefusesRedirectOffGateway(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/steal", http.StatusFound)
	}))
	defer server.Close()

	target := serverTarget(t, server)
	client := newPinnedClient(target)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, gatewayURL("http", target, "/"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := doRequest(t.Context(), client, req); !errors.Is(err, errOffGateway) {
		t.Fatalf("got %v, want errOffGateway", err)
	}
}

func TestPinnedClientRefusesDialingOtherHosts(t *testing.T) {
	client := newPinnedClient(Target{IP: "127.0.0.1", Port: "8080"})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := doRequest(t.Context(), client, req); !errors.Is(err, errOffGateway) {
		t.Fatalf("got %v, want errOffGateway", err)
	}
}

func TestResponseBodyIsBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		chunk := strings.Repeat("a", 4096)
		for written := 0; written <= maxResponseBody; written += len(chunk) {
			_, _ = io.WriteString(w, chunk)
		}
	}))
	defer server.Close()

	target := serverTarget(t, server)
	client := newPinnedClient(target)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, gatewayURL("http", target, "/"), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, body, err := doRequest(t.Context(), client, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != maxResponseBody {
		t.Fatalf("body length = %d, want the %d byte cap", len(body), maxResponseBody)
	}
}

func TestProbeCollectsFingerprint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<html>router login page</html>")
	}))
	defer server.Close()

	fp := probeFingerprint(t, serverTarget(t, server))
	if !fp.Reachable || fp.Status != http.StatusOK || fp.Scheme != "http" {
		t.Fatalf("unexpected fingerprint: %#v", fp)
	}
	if !fp.BodyContains("router login page") {
		t.Fatalf("body missing: %q", fp.Body)
	}
}

func TestProbeReportsUnreachableGateway(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()

	_, err = Probe(t.Context(), Target{IP: "127.0.0.1", Port: port})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}

	if _, err := Probe(t.Context(), Target{}); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("missing address: got %v, want ErrUnreachable", err)
	}
}
