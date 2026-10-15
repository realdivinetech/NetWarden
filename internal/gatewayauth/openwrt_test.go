package gatewayauth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func openwrtServer(user, pass string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<html><title>LuCI - Lua Configuration Interface</title><link rel="stylesheet" href="/luci-static/resources/cascade.css"/></html>`)
	})
	mux.HandleFunc("/ubus", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || len(request.Params) < 4 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var login struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		_ = json.Unmarshal(request.Params[3], &login)
		w.Header().Set("Content-Type", "application/json")
		if login.Username == user && login.Password == pass {
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[0,{"ubus_rpc_session":"1122334455667788","timeout":300,"expires":299,"acls":{}}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[6,{"message":"Invalid username or password"}]}`)
	})
	return httptest.NewServer(mux)
}

func openwrtLegacyServer(user, pass string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<html><title>LuCI</title><link href="/luci-static/style.css"/></html>`)
	})
	mux.HandleFunc("/ubus", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/cgi-bin/luci/rpc/auth", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Params []string `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || len(request.Params) < 2 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if request.Params[0] == user && request.Params[1] == pass {
			_, _ = io.WriteString(w, `{"result":"8f0d1a2b3c4d5e6f"}`)
			return
		}
		_, _ = io.WriteString(w, `{"error":{"message":"Insufficient privileges"}}`)
	})
	return httptest.NewServer(mux)
}

func TestOpenWrtVerifierSelectsOnLuCIMarkers(t *testing.T) {
	verifier := &OpenWrtVerifier{}
	if !verifier.Match(Fingerprint{Body: `<link href="/luci-static/resources/cascade.css"/>`}) {
		t.Fatal("luci-static should select the openwrt adapter")
	}
	if verifier.Match(Fingerprint{Body: "<html>generic router</html>"}) {
		t.Fatal("generic page must not select the openwrt adapter")
	}
}

func TestOpenWrtVerifierAcceptsCorrectCredentials(t *testing.T) {
	server := openwrtServer("root", "correct horse")
	defer server.Close()
	target := serverTarget(t, server)
	fp := probeFingerprint(t, target)

	result, err := (&OpenWrtVerifier{}).Verify(t.Context(), target, fp, Credentials{Username: "root", Password: "correct horse"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.Verified || result.Strategy != "openwrt-luci" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestOpenWrtVerifierRejectsWrongPassword(t *testing.T) {
	server := openwrtServer("root", "correct horse")
	defer server.Close()
	target := serverTarget(t, server)
	fp := probeFingerprint(t, target)

	result, err := (&OpenWrtVerifier{}).Verify(t.Context(), target, fp, Credentials{Username: "root", Password: "wrong"})
	if err == nil {
		t.Fatal("wrong password must be refused")
	}
	if !strings.Contains(err.Error(), "Invalid username or password") {
		t.Fatalf("expected the router's refusal detail, got %v", err)
	}
	if result.Verified {
		t.Fatal("refused credentials must not verify")
	}
}

func TestOpenWrtVerifierFallsBackToLegacyRpc(t *testing.T) {
	server := openwrtLegacyServer("root", "correct horse")
	defer server.Close()
	target := serverTarget(t, server)
	fp := probeFingerprint(t, target)

	result, err := (&OpenWrtVerifier{}).Verify(t.Context(), target, fp, Credentials{Username: "root", Password: "correct horse"})
	if err != nil {
		t.Fatalf("legacy rpc login should work: %v", err)
	}
	if !result.Verified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestOpenWrtVerifierLegacyRejectsWrongPassword(t *testing.T) {
	server := openwrtLegacyServer("root", "correct horse")
	defer server.Close()
	target := serverTarget(t, server)
	fp := probeFingerprint(t, target)

	_, err := (&OpenWrtVerifier{}).Verify(t.Context(), target, fp, Credentials{Username: "root", Password: "wrong"})
	if err == nil {
		t.Fatal("wrong password must be refused")
	}
	if !strings.Contains(err.Error(), "Insufficient privileges") {
		t.Fatalf("expected the legacy refusal detail, got %v", err)
	}
}
