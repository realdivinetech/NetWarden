package gatewayauth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// basicServer answers with an RFC 7617 challenge and accepts one pair.
func basicServer(user, pass string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, ok := r.BasicAuth()
		if ok && gotUser == user && gotPass == pass {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "router index")
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="NETGEAR"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
}

func TestChallengeHasScheme(t *testing.T) {
	cases := []struct {
		header string
		scheme string
		want   bool
	}{
		{`Basic realm="x"`, "basic", true},
		{`Digest realm="x", nonce="n"`, "digest", true},
		{`Digest realm="x", nonce="n"`, "basic", false},
		{`Basic realm="x", Digest realm="y", nonce="n"`, "digest", true},
		{`basic`, "basic", true},
		{`Basic`, "digest", false},
		{``, "basic", false},
	}
	for _, test := range cases {
		if got := challengeHasScheme(test.header, test.scheme); got != test.want {
			t.Errorf("challengeHasScheme(%q, %q) = %v, want %v", test.header, test.scheme, got, test.want)
		}
	}
}

func TestBasicVerifierAcceptsCorrectCredentials(t *testing.T) {
	server := basicServer("admin", "correct horse")
	defer server.Close()
	target := serverTarget(t, server)
	fp := probeFingerprint(t, target)

	verifier := &BasicVerifier{}
	if !verifier.Match(fp) {
		t.Fatal("basic challenge should select the basic adapter")
	}
	result, err := verifier.Verify(t.Context(), target, fp, credentials())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.Verified || result.Strategy != "http-basic" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestBasicVerifierRejectsWrongPassword(t *testing.T) {
	server := basicServer("admin", "correct horse")
	defer server.Close()
	target := serverTarget(t, server)
	fp := probeFingerprint(t, target)

	verifier := &BasicVerifier{}
	result, err := verifier.Verify(t.Context(), target, fp, Credentials{Username: "admin", Password: "wrong"})
	if err == nil {
		t.Fatal("wrong password must be refused")
	}
	if result.Verified {
		t.Fatal("refused credentials must not verify")
	}
}

func TestBasicVerifierReportsUnreachableGateway(t *testing.T) {
	server := basicServer("admin", "correct horse")
	target := serverTarget(t, server)
	server.Close()

	verifier := &BasicVerifier{}
	_, err := verifier.Verify(t.Context(), target, Fingerprint{Scheme: "http"}, credentials())
	if err == nil {
		t.Fatal("a closed gateway must fail")
	}
}
