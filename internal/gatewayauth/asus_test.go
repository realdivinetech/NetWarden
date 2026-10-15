package gatewayauth

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func asusServer(user, pass string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<html><head><script src="/js/unifi_utils.js"></script></head>
<body><form id="login_form" action="/login.cgi"><input name="login_authorization"/></form></body></html>`)
	})
	mux.HandleFunc("/login.cgi", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(r.FormValue("login_authorization"))
		if err == nil && string(raw) == user+":"+pass && r.FormValue("current_page") == "Main_Login.asp" {
			http.SetCookie(w, &http.Cookie{Name: "asus_token", Value: "tok-123", Path: "/"})
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"asus_token":"tok-123","next_page":"index.asp"}`)
			return
		}
		_, _ = io.WriteString(w, `{"error_status":"Login failed"}`)
	})
	return httptest.NewServer(mux)
}

func TestASUSVerifierSelectsOnFirmwareMarkers(t *testing.T) {
	verifier := &ASUSVerifier{}
	if !verifier.Match(Fingerprint{Body: `<form action="/login.cgi"><input name="login_authorization"/></form>`}) {
		t.Fatal("login_authorization should select the asus adapter")
	}
	// net/http canonicalises response headers, so Model_Name arrives as
	// Model_name — the adapter reads it through Header.Get, which canonicalises
	// the lookup key the same way.
	if !verifier.Match(Fingerprint{Header: http.Header{"Model_name": []string{"RT-AX88U"}}}) {
		t.Fatal("Model_Name header should select the asus adapter")
	}
	if verifier.Match(Fingerprint{Body: "<html>generic router</html>"}) {
		t.Fatal("generic page must not select the asus adapter")
	}
}

func TestASUSVerifierAcceptsCorrectCredentials(t *testing.T) {
	server := asusServer("admin", "correct horse")
	defer server.Close()
	target := serverTarget(t, server)
	fp := probeFingerprint(t, target)

	result, err := (&ASUSVerifier{}).Verify(t.Context(), target, fp, credentials())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.Verified || result.Strategy != "asuswrt" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestASUSVerifierRejectsWrongPassword(t *testing.T) {
	server := asusServer("admin", "correct horse")
	defer server.Close()
	target := serverTarget(t, server)
	fp := probeFingerprint(t, target)

	result, err := (&ASUSVerifier{}).Verify(t.Context(), target, fp, Credentials{Username: "admin", Password: "wrong"})
	if err == nil {
		t.Fatal("wrong password must be refused")
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if result.Verified {
		t.Fatal("refused credentials must not verify")
	}
}
