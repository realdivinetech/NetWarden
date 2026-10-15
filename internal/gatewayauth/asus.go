package gatewayauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ASUSVerifier authenticates ASUSWRT gateways through /login.cgi, which takes
// base64(username:password) in login_authorization and answers with a JSON
// body carrying an asus_token session cookie.
type ASUSVerifier struct{}

// Name implements Verifier.
func (v *ASUSVerifier) Name() string { return "asuswrt" }

// UsernameRequired implements Verifier: ASUSWRT accepts an empty username on
// some firmware, so the field stays optional.
func (v *ASUSVerifier) UsernameRequired() bool { return false }

// Match implements Verifier.
func (v *ASUSVerifier) Match(fp Fingerprint) bool {
	if fp.Header.Get("Model_Name") != "" {
		return true
	}
	return fp.BodyContainsAny("login_authorization", "asus_token", "Main_Login.asp", "asuswrt")
}

// Verify implements Verifier with a single login.cgi attempt.
func (v *ASUSVerifier) Verify(ctx context.Context, target Target, fp Fingerprint, creds Credentials) (Result, error) {
	client := newPinnedClientWithJar(target, true)
	scheme := fp.Scheme

	authorization := base64.StdEncoding.EncodeToString([]byte(creds.Username + ":" + creds.Password))
	form := url.Values{}
	form.Set("group_id", "")
	form.Set("action_mode", "")
	form.Set("action_script", "")
	form.Set("action_wait", "5")
	form.Set("current_page", "Main_Login.asp")
	form.Set("next_page", "index.asp")
	form.Set("login_authorization", authorization)

	endpoint := gatewayURL(scheme, target, "/login.cgi")
	resp, body, err := postForm(ctx, client, endpoint, form, map[string]string{
		"Referer": gatewayURL(scheme, target, "/Main_Login.asp"),
		"Accept":  "application/json, text/javascript, */*; q=0.01",
	})
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	if resp.Body != nil {
		resp.Body.Close()
	}

	final := ""
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	if strings.Contains(final, "error_status") {
		return Result{}, fmt.Errorf("router refused the credentials")
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return Result{}, fmt.Errorf("router refused the credentials (%s)", describeStatus(resp.StatusCode))
	}

	// Success is proven by the session cookie or its JSON echo.
	if client.Jar != nil {
		if cookieURL, err := url.Parse(gatewayURL(scheme, target, "/")); err == nil {
			for _, cookie := range client.Jar.Cookies(cookieURL) {
				if cookie.Name == "asus_token" && cookie.Value != "" {
					return Result{Verified: true, Strategy: v.Name()}, nil
				}
			}
		}
	}
	var reply struct {
		Token string `json:"asus_token"`
	}
	if err := json.Unmarshal(body, &reply); err == nil && reply.Token != "" {
		return Result{Verified: true, Strategy: v.Name()}, nil
	}
	if pageContains(string(body), "asus_token") {
		return Result{Verified: true, Strategy: v.Name()}, nil
	}
	if pageContains(string(body), "error_status") {
		return Result{}, fmt.Errorf("router refused the credentials")
	}
	return Result{}, fmt.Errorf("unrecognized reply from the router (%s)", describeStatus(resp.StatusCode))
}
