package gatewayauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// HuaweiVerifier authenticates Huawei/HG optical terminals (the HG8245M,
// HG8546M and relatives) that serve a form login at /login.cgi:
//
//  1. POST /asp/GetRandCount.asp returns a one-shot login token;
//  2. a "Cookie" cookie carrying the UI language is set;
//  3. POST /login.cgi submits UserName, base64(PassWord), Language and
//     x.X_HW_Token.
//
// The page itself documents this flow (LoginSubmit in the login page script),
// so the adapter follows it literally instead of guessing.
type HuaweiVerifier struct{}

// Name implements Verifier.
func (v *HuaweiVerifier) Name() string { return "huawei-ont" }

// UsernameRequired implements Verifier.
func (v *HuaweiVerifier) UsernameRequired() bool { return true }

// Match implements Verifier.
func (v *HuaweiVerifier) Match(fp Fingerprint) bool {
	return fp.BodyContainsAny("function GetRandCnt", "x.X_HW_Token", "/asp/GetRandCount.asp") ||
		(fp.BodyContains("txt_Username") && fp.BodyContains("login.cgi"))
}

var (
	huaweiLanguageRE = regexp.MustCompile(`var\s+Language\s*=\s*'([^']*)'`)
	huaweiNonceRE    = regexp.MustCompile(`GetRandCnt\s*\(\s*\)\s*\{\s*return\s*'([0-9a-fA-F]+)'`)
	huaweiPageNameRE = regexp.MustCompile(`var\s+pageName\s*=\s*'([^']*)'`)
)

// huaweiLoginRejection lists markers that mean the login reply itself is still
// (or again) the login form. Only strong, form-specific markers are listed:
// shared page scripts on this firmware also mention login.asp, LoginTimes and
// FailStat, so those would misclassify successful logins.
var huaweiLoginRejection = []string{
	"txt_Username",
	"txt_Password",
	"error_status",
}

// Verify implements Verifier with exactly one login.cgi attempt.
func (v *HuaweiVerifier) Verify(ctx context.Context, target Target, fp Fingerprint, creds Credentials) (Result, error) {
	client := newPinnedClientWithJar(target, true)
	scheme := fp.Scheme

	language := "english"
	if match := huaweiLanguageRE.FindStringSubmatch(fp.Body); len(match) == 2 && match[1] != "" {
		language = match[1]
	}
	fallbackToken := ""
	if match := huaweiNonceRE.FindStringSubmatch(fp.Body); len(match) == 2 {
		fallbackToken = match[1]
	}

	// The firmware fetches a fresh token immediately before every login.
	token := fallbackToken
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, gatewayURL(scheme, target, "/asp/GetRandCount.asp"), strings.NewReader(""))
	if err != nil {
		return Result{}, err
	}
	tokenReq.Header.Set("User-Agent", userAgent)
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp, body, reqErr := doRequest(ctx, client, tokenReq); reqErr == nil {
		if resp.Body != nil {
			resp.Body.Close()
		}
		// Some firmwares prefix the token with a UTF-8 BOM that browsers strip
		// during decoding; TrimSpace leaves U+FEFF in place, which corrupts it.
		candidate := strings.TrimSpace(strings.TrimPrefix(string(body), "\uFEFF"))
		if candidate != "" {
			token = candidate
		}
	}
	if token == "" {
		return Result{}, fmt.Errorf("could not obtain the router login token")
	}

	if client.Jar != nil {
		if cookieURL, err := url.Parse(gatewayURL(scheme, target, "/")); err == nil {
			client.Jar.SetCookies(cookieURL, []*http.Cookie{{
				Name:  "Cookie",
				Value: "body:Language:" + language + ":id=-1",
				Path:  "/",
			}})
		}
	}

	form := url.Values{}
	form.Set("UserName", creds.Username)
	form.Set("PassWord", jsBase64(creds.Password))
	form.Set("Language", language)
	form.Set("x.X_HW_Token", token)

	resp, body, err := postForm(ctx, client, gatewayURL(scheme, target, "/login.cgi"), form, map[string]string{
		"Referer": gatewayURL(scheme, target, "/"),
		"Accept":  "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	})
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	if resp.Body != nil {
		resp.Body.Close()
	}
	finalPath := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalPath = resp.Request.URL.Path
	}
	switch classifyFormResponse(resp.StatusCode, body, finalPath, huaweiLoginRejection, nil) {
	case formRefused:
		return Result{}, fmt.Errorf("router refused the credentials (%s)", describeStatus(resp.StatusCode))
	case formAccepted:
		return Result{Verified: true, Strategy: v.Name()}, nil
	}

	// Ambiguous reply: this firmware answers a successful login with a small
	// "Waiting..." page that JS-redirects to the real home (index.asp), while a
	// failed login redirects back to "/". Follow the redirect the router itself
	// chose and require a page that is neither the login form nor the stub.
	for _, path := range huaweiLandingCandidates(body) {
		landReq, err := http.NewRequestWithContext(ctx, http.MethodGet, gatewayURL(scheme, target, path), nil)
		if err != nil {
			return Result{}, err
		}
		landReq.Header.Set("User-Agent", userAgent)
		landResp, landBody, err := doRequest(ctx, client, landReq)
		if err != nil {
			return Result{}, fmt.Errorf("%w: %v", ErrUnreachable, err)
		}
		if landResp.Body != nil {
			landResp.Body.Close()
		}
		if landResp.StatusCode >= 400 || huaweiServesLoginForm(landBody) || huaweiIsRedirectStub(landBody) {
			continue
		}
		return Result{Verified: true, Strategy: v.Name()}, nil
	}
	return Result{}, fmt.Errorf("router refused the credentials")
}

// huaweiLandingCandidates picks the pages worth checking after an ambiguous
// login.cgi reply: whatever page the reply redirects to first, then "/".
func huaweiLandingCandidates(loginBody []byte) []string {
	paths := []string{"/"}
	if match := huaweiPageNameRE.FindStringSubmatch(string(loginBody)); len(match) == 2 {
		chosen := strings.TrimPrefix(match[1], "/")
		if chosen != "" && chosen != "/" && !strings.HasPrefix(chosen, "login") {
			paths = append([]string{chosen}, paths...)
		}
	}
	return paths
}

// huaweiServesLoginForm reports whether a page is the (still logged-out) login
// screen, using only strong form-specific markers.
func huaweiServesLoginForm(body []byte) bool {
	low := strings.ToLower(string(body))
	return strings.Contains(low, "txt_username") || strings.Contains(low, "loginsubmit")
}

// huaweiIsRedirectStub recognizes the tiny "Waiting..." page the firmware
// serves for paths it does not really have; it must not count as a home page.
func huaweiIsRedirectStub(body []byte) bool {
	low := strings.ToLower(string(body))
	return strings.Contains(low, "<title>waiting") || strings.Contains(low, "top.location.replace")
}
