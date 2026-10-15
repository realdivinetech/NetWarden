package gatewayauth

import (
	"crypto/md5" //nolint:gosec // RouterOS legacy login mandates MD5
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

// startRouterOS serves a scripted RouterOS API conversation and points the
// adapter at it for the duration of the test.
func startRouterOS(t *testing.T, handle func(conn net.Conn)) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				handle(conn)
			}()
		}
	}()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	previous := mikroTikAPIPort
	mikroTikAPIPort = port
	t.Cleanup(func() { mikroTikAPIPort = previous })
}

func webFigFingerprint() Fingerprint {
	return Fingerprint{Reachable: true, Scheme: "http", Body: "<html><title>WebFig</title>RouterOS</html>"}
}

func TestMikroTikVerifierSelectsOnFirmwareMarkers(t *testing.T) {
	verifier := &MikroTikVerifier{}
	if !verifier.Match(webFigFingerprint()) {
		t.Fatal("webfig body should select the routeros adapter")
	}
	if !verifier.Match(Fingerprint{Header: map[string][]string{"Server": {"MikroTik"}}}) {
		t.Fatal("Server header should select the routeros adapter")
	}
	if verifier.Match(Fingerprint{Body: "<html>generic router</html>"}) {
		t.Fatal("generic page must not select the routeros adapter")
	}
}

func TestMikroTikVerifierAcceptsModernLogin(t *testing.T) {
	startRouterOS(t, func(conn net.Conn) {
		words, err := readRouterOSWords(conn)
		if err != nil {
			return
		}
		if len(words) != 3 || words[0] != "/login" || words[1] != "=name=admin" || words[2] != "=password=correct horse" {
			_ = writeRouterOSWords(conn, "!fatal", "=message=unexpected login sentence")
			return
		}
		_ = writeRouterOSWords(conn, "!done")
	})
	target := Target{IP: "127.0.0.1"}

	result, err := (&MikroTikVerifier{}).Verify(t.Context(), target, webFigFingerprint(), credentials())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.Verified || result.Strategy != "mikrotik-routeros-api" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestMikroTikVerifierRejectsWrongPassword(t *testing.T) {
	startRouterOS(t, func(conn net.Conn) {
		if _, err := readRouterOSWords(conn); err != nil {
			return
		}
		_ = writeRouterOSWords(conn, "!trap", "=message=invalid user name or password")
	})
	target := Target{IP: "127.0.0.1"}

	result, err := (&MikroTikVerifier{}).Verify(t.Context(), target, webFigFingerprint(), credentials())
	if err == nil {
		t.Fatal("wrong password must be refused")
	}
	if !strings.Contains(err.Error(), "invalid user name or password") {
		t.Fatalf("expected the router's refusal detail, got %v", err)
	}
	if result.Verified {
		t.Fatal("refused credentials must not verify")
	}
}

func TestMikroTikVerifierAnswersLegacyChallenge(t *testing.T) {
	const challenge = "deadbeefcafebabe0123456789abcdef"
	digest := md5.New() //nolint:gosec // mandated by RouterOS legacy login
	digest.Write([]byte{0x00})
	digest.Write([]byte("correct horse"))
	challengeBytes, err := hex.DecodeString(challenge)
	if err != nil {
		t.Fatal(err)
	}
	digest.Write(challengeBytes)
	wantResponse := "00" + hex.EncodeToString(digest.Sum(nil))

	startRouterOS(t, func(conn net.Conn) {
		if _, err := readRouterOSWords(conn); err != nil {
			return
		}
		if err := writeRouterOSWords(conn, "!done", "=ret="+challenge); err != nil {
			return
		}
		words, err := readRouterOSWords(conn)
		if err != nil {
			return
		}
		if len(words) != 3 || words[0] != "/login" || words[1] != "=name=admin" || words[2] != "=response="+wantResponse {
			_ = writeRouterOSWords(conn, "!trap", "=message=wrong response")
			return
		}
		_ = writeRouterOSWords(conn, "!done")
	})
	target := Target{IP: "127.0.0.1"}

	result, err := (&MikroTikVerifier{}).Verify(t.Context(), target, webFigFingerprint(), credentials())
	if err != nil {
		t.Fatalf("legacy challenge flow: %v", err)
	}
	if !result.Verified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestMikroTikVerifierReportsClosedAPIPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()
	previous := mikroTikAPIPort
	mikroTikAPIPort = port
	t.Cleanup(func() { mikroTikAPIPort = previous })

	target := Target{IP: "127.0.0.1"}
	if _, err := (&MikroTikVerifier{}).Verify(t.Context(), target, webFigFingerprint(), credentials()); err == nil {
		t.Fatal("a closed API port must fail")
	}
}
