package gatewayauth

import (
	"encoding/base64"
	"net/http"
	"testing"
)

func TestJSBase64MatchesBrowserBtoa(t *testing.T) {
	if got, want := jsBase64("correct horse"), base64.StdEncoding.EncodeToString([]byte("correct horse")); got != want {
		t.Fatalf("jsBase64 ASCII = %q, want %q", got, want)
	}
	// btoa() keeps only the low byte of each character, and so must we.
	if got := jsBase64("é"); got != "6Q==" {
		t.Fatalf("jsBase64 non-ASCII = %q, want 6Q==", got)
	}
}

func TestClassifyFormResponse(t *testing.T) {
	loginPage := []byte(`<html><input id="txt_Username"/></html>`)
	indexPage := []byte(`<html>device overview</html>`)
	cases := []struct {
		name      string
		status    int
		body      []byte
		finalPath string
		want      formResult
	}{
		{"unauthorized", http.StatusUnauthorized, indexPage, "/login.cgi", formRefused},
		{"forbidden", http.StatusForbidden, indexPage, "/login.cgi", formRefused},
		{"rejection marker wins", http.StatusOK, loginPage, "/index.asp", formRefused},
		{"stuck on login page", http.StatusOK, indexPage, "/login.asp", formRefused},
		{"server error", http.StatusInternalServerError, indexPage, "/login.cgi", formRefused},
		{"empty acknowledged reply", http.StatusOK, nil, "/login.cgi", formUnrecognized},
		{"generic success page", http.StatusOK, indexPage, "/index.asp", formUnrecognized},
		{"acceptance marker", http.StatusOK, []byte(`<html>login succeeded</html>`), "/index.asp", formAccepted},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := classifyFormResponse(test.status, test.body, test.finalPath, huaweiLoginRejection, []string{"login succeeded"})
			if got != test.want {
				t.Fatalf("classifyFormResponse = %v, want %v", got, test.want)
			}
		})
	}
}
