package gatewayauth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// huaweiLoginPage is a sanitized excerpt of the real HG-series login page:
// only the markers the adapter keys on, no device identifiers.
const huaweiLoginPage = `<html><head><script src="/js/md5.js"></script>
<script>
function GetRandCnt(){ return 'a1b2c3d4'; }
var Language = 'english';
function LoginSubmit() {
  var token = 'x.X_HW_Token';
  location.href = '/asp/GetRandCount.asp';
}
</script></head><body>
<form method="post" action="/login.cgi">
  <input id="txt_Username" name="UserName" />
  <input id="txt_Password" name="PassWord" />
</form>
</body></html>`

type huaweiState struct {
	loggedIn      bool
	brokenToken   bool
	tokenRequests int
}

func huaweiServer() (*httptest.Server, *huaweiState) {
	state := &huaweiState{}
	mux := http.NewServeMux()
	mux.HandleFunc("/asp/GetRandCount.asp", func(w http.ResponseWriter, r *http.Request) {
		state.tokenRequests++
		if state.brokenToken {
			return
		}
		_, _ = io.WriteString(w, "a1b2c3d4")
	})
	mux.HandleFunc("/login.cgi", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.FormValue("UserName") == "admin" &&
			r.FormValue("PassWord") == jsBase64("correct horse") &&
			r.FormValue("Language") == "english" &&
			r.FormValue("x.X_HW_Token") == "a1b2c3d4" {
			state.loggedIn = true
			_, _ = io.WriteString(w, "<html>device information page</html>")
			return
		}
		_, _ = io.WriteString(w, `<html><body><input id="txt_Username"/>LoginTimes</body></html>`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if state.loggedIn {
			_, _ = io.WriteString(w, "<html>status overview page</html>")
			return
		}
		_, _ = io.WriteString(w, huaweiLoginPage)
	})
	return httptest.NewServer(mux), state
}

func TestHuaweiVerifierSelectsOnLoginMarkers(t *testing.T) {
	verifier := &HuaweiVerifier{}
	if !verifier.Match(Fingerprint{Body: huaweiLoginPage}) {
		t.Fatal("huawei login markers should select the adapter")
	}
	if verifier.Match(Fingerprint{Body: "<html>generic router</html>"}) {
		t.Fatal("generic page must not select the huawei adapter")
	}
}

func TestHuaweiVerifierAcceptsCorrectCredentials(t *testing.T) {
	server, state := huaweiServer()
	defer server.Close()
	target := serverTarget(t, server)
	fp := probeFingerprint(t, target)

	result, err := (&HuaweiVerifier{}).Verify(t.Context(), target, fp, credentials())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.Verified || result.Strategy != "huawei-ont" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if !state.loggedIn || state.tokenRequests == 0 {
		t.Fatalf("server saw login=%v tokenRequests=%d", state.loggedIn, state.tokenRequests)
	}
}

func TestHuaweiVerifierRejectsWrongPassword(t *testing.T) {
	server, _ := huaweiServer()
	defer server.Close()
	target := serverTarget(t, server)
	fp := probeFingerprint(t, target)

	result, err := (&HuaweiVerifier{}).Verify(t.Context(), target, fp, Credentials{Username: "admin", Password: "wrong"})
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

func TestHuaweiVerifierFallsBackToPageToken(t *testing.T) {
	server, state := huaweiServer()
	defer server.Close()
	state.brokenToken = true
	target := serverTarget(t, server)
	fp := probeFingerprint(t, target)

	if _, err := (&HuaweiVerifier{}).Verify(t.Context(), target, fp, credentials()); err != nil {
		t.Fatalf("page-embedded token fallback should work: %v", err)
	}
}

func TestHuaweiVerifierFailsWithoutAnyToken(t *testing.T) {
	server, state := huaweiServer()
	defer server.Close()
	state.brokenToken = true
	target := serverTarget(t, server)
	fp := probeFingerprint(t, target)
	fp.Body = strings.Replace(fp.Body, "a1b2c3d4", "", 1)

	if _, err := (&HuaweiVerifier{}).Verify(t.Context(), target, fp, credentials()); err == nil {
		t.Fatal("missing token must fail instead of guessing")
	}
}
