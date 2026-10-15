package gatewayauth

import (
	"crypto/md5" //nolint:gosec // digest authentication mandates MD5
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// digestServer implements enough RFC 7616 Digest (qop=auth, MD5) to validate
// whatever the client produces.
func digestServer(user, pass string) *httptest.Server {
	const (
		realm = "router"
		nonce = "0a4f113bfeedbeef"
	)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Digest ") {
			w.Header().Set("WWW-Authenticate", `Digest realm="`+realm+`", nonce="`+nonce+`", qop="auth", algorithm=MD5`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fields := map[string]string{}
		for _, match := range digestPairRE.FindAllStringSubmatch(authorization, -1) {
			if len(match) == 3 {
				fields[strings.ToLower(match[1])] = strings.Trim(match[2], `"`)
			}
		}
		ha1 := digestHex(md5.New, fields["username"], realm, pass)
		if fields["username"] != user {
			ha1 = digestHex(md5.New, fields["username"], realm, "not-the-password")
		}
		ha2 := digestHex(md5.New, http.MethodGet, fields["uri"])
		expected := digestHex(md5.New, ha1, fields["nonce"], fields["nc"], fields["cnonce"], "auth", ha2)
		if fields["response"] != expected {
			w.Header().Set("WWW-Authenticate", `Digest realm="`+realm+`", nonce="`+nonce+`", qop="auth", algorithm=MD5`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "router index")
	}))
}

func TestParseDigestChallenge(t *testing.T) {
	challenge, ok := parseDigestChallenge(`Digest realm="router", nonce="abc", qop="auth", opaque="op", algorithm=SHA-256`)
	if !ok {
		t.Fatal("challenge should parse")
	}
	if challenge.realm != "router" || challenge.nonce != "abc" || challenge.qop != "auth" || challenge.opaque != "op" || challenge.algorithm != "SHA-256" {
		t.Fatalf("unexpected challenge: %#v", challenge)
	}
	if _, ok := parseDigestChallenge(`Basic realm="router"`); ok {
		t.Fatal("basic header must not parse as digest")
	}
	if _, ok := parseDigestChallenge(`Digest realm="router"`); ok {
		t.Fatal("a challenge without nonce must be refused")
	}
	packed, ok := parseDigestChallenge(`Digest realm="router", nonce="abc", Basic realm="other"`)
	if !ok || packed.realm != "router" || packed.nonce != "abc" {
		t.Fatalf("packed challenge mishandled: %#v ok=%v", packed, ok)
	}
}

func TestBuildDigestAuthorizationSelfConsistent(t *testing.T) {
	challenge := digestChallenge{realm: "router", nonce: "abc", qop: "auth", algorithm: "MD5"}
	header, err := buildDigestAuthorization(challenge, http.MethodGet, "/", "admin", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(header, "Digest ") || !strings.Contains(header, `username="admin"`) {
		t.Fatalf("unexpected header: %s", header)
	}
	fields := map[string]string{}
	for _, match := range digestPairRE.FindAllStringSubmatch(header, -1) {
		if len(match) == 3 {
			fields[strings.ToLower(match[1])] = strings.Trim(match[2], `"`)
		}
	}
	ha1 := digestHex(md5.New, "admin", "router", "secret")
	ha2 := digestHex(md5.New, http.MethodGet, "/")
	expected := digestHex(md5.New, ha1, "abc", fields["nc"], fields["cnonce"], "auth", ha2)
	if fields["response"] != expected {
		t.Fatalf("response %s does not match recomputed %s", fields["response"], expected)
	}
}

func TestBuildDigestAuthorizationRefusesUnsupportedOptions(t *testing.T) {
	if _, err := buildDigestAuthorization(digestChallenge{realm: "r", nonce: "n", algorithm: "MD4"}, http.MethodGet, "/", "u", "p"); err == nil {
		t.Fatal("unsupported algorithm must be refused")
	}
	if _, err := buildDigestAuthorization(digestChallenge{realm: "r", nonce: "n", qop: "auth-int", algorithm: "MD5"}, http.MethodGet, "/", "u", "p"); err == nil {
		t.Fatal("unsupported qop must be refused")
	}
}

func TestDigestVerifierAcceptsCorrectCredentials(t *testing.T) {
	server := digestServer("admin", "correct horse")
	defer server.Close()
	target := serverTarget(t, server)
	fp := probeFingerprint(t, target)

	verifier := &DigestVerifier{}
	if !verifier.Match(fp) {
		t.Fatal("digest challenge should select the digest adapter")
	}
	result, err := verifier.Verify(t.Context(), target, fp, credentials())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.Verified || result.Strategy != "http-digest" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestDigestVerifierRejectsWrongPassword(t *testing.T) {
	server := digestServer("admin", "correct horse")
	defer server.Close()
	target := serverTarget(t, server)
	fp := probeFingerprint(t, target)

	verifier := &DigestVerifier{}
	result, err := verifier.Verify(t.Context(), target, fp, Credentials{Username: "admin", Password: "wrong"})
	if err == nil {
		t.Fatal("wrong password must be refused")
	}
	if result.Verified {
		t.Fatal("refused credentials must not verify")
	}
}
