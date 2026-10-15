package gatewayauth

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Temporary live probe against the real router. Skipped unless
// NETWARDEN_LIVE_USER / NETWARDEN_LIVE_PASS are set.
func TestLiveHuaweiLogin(t *testing.T) {
	user := os.Getenv("NETWARDEN_LIVE_USER")
	pass := os.Getenv("NETWARDEN_LIVE_PASS")
	if user == "" || pass == "" {
		t.Skip("live credentials not provided")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	target := Target{IP: "192.168.100.1"}
	fp, err := Probe(ctx, target)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	t.Logf("fingerprint reachable=%v status=%d len=%d scheme=%s", fp.Reachable, fp.Status, len(fp.Body), fp.Scheme)

	client := newPinnedClientWithJar(target, true)
	base := gatewayURL(fp.Scheme, target, "/")

	language := "english"
	if match := huaweiLanguageRE.FindStringSubmatch(fp.Body); len(match) == 2 && match[1] != "" {
		language = match[1]
	}
	token := ""
	if match := huaweiNonceRE.FindStringSubmatch(fp.Body); len(match) == 2 {
		token = match[1]
	}
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, gatewayURL(fp.Scheme, target, "/asp/GetRandCount.asp"), strings.NewReader(""))
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	tokenReq.Header.Set("User-Agent", userAgent)
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp, body, reqErr := doRequest(ctx, client, tokenReq); reqErr == nil {
		if resp.Body != nil {
			resp.Body.Close()
		}
		if candidate := strings.TrimSpace(strings.TrimPrefix(string(body), "\uFEFF")); candidate != "" {
			token = candidate
		}
	}
	t.Logf("language=%q token=%q", language, token)

	if client.Jar != nil {
		if cookieURL, err := url.Parse(base); err == nil {
			client.Jar.SetCookies(cookieURL, []*http.Cookie{{
				Name:  "Cookie",
				Value: "body:Language:" + language + ":id=-1",
				Path:  "/",
			}})
		}
	}

	form := url.Values{}
	form.Set("UserName", user)
	form.Set("PassWord", jsBase64(pass))
	form.Set("Language", language)
	form.Set("x.X_HW_Token", token)
	resp, body, err := postForm(ctx, client, gatewayURL(fp.Scheme, target, "/login.cgi"), form, map[string]string{
		"Referer": base,
		"Accept":  "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	})
	if err != nil {
		t.Fatalf("login.cgi: %v", err)
	}
	if resp.Body != nil {
		resp.Body.Close()
	}
	finalPath := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalPath = resp.Request.URL.Path
	}
	t.Logf("login.cgi status=%d len=%d finalPath=%q", resp.StatusCode, len(body), finalPath)
	snippet := string(body)
	if len(snippet) > 1600 {
		snippet = snippet[:1600]
	}
	t.Logf("login.cgi body:\n%s", snippet)
	t.Logf("classify=%v", classifyFormResponse(resp.StatusCode, body, finalPath, huaweiLoginRejection, nil))
	lowBody := strings.ToLower(string(body))
	for _, marker := range huaweiLoginRejection {
		if strings.Contains(lowBody, strings.ToLower(marker)) {
			t.Logf("  login.cgi contains marker %q", marker)
		}
	}

	for _, path := range []string{"/", "/html/index.html", "/index.asp", "/html/index.asp", "/login.asp"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, gatewayURL(fp.Scheme, target, path), nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", userAgent)
		landResp, landBody, err := doRequest(ctx, client, req)
		if err != nil {
			t.Logf("GET %s: %v", path, err)
			continue
		}
		if landResp.Body != nil {
			landResp.Body.Close()
		}
		low := strings.ToLower(string(landBody))
		loginForm := strings.Contains(low, "txt_username") || strings.Contains(low, "loginsubmit")
		t.Logf("GET %s -> status=%d len=%d loginForm=%v classify=%v", path, landResp.StatusCode, len(landBody), loginForm,
			classifyFormResponse(landResp.StatusCode, landBody, path, huaweiLoginRejection, nil))
		for _, marker := range huaweiLoginRejection {
			if strings.Contains(low, strings.ToLower(marker)) {
				t.Logf("  contains marker %q", marker)
			}
		}
		if !loginForm && len(landBody) > 0 {
			snip := string(landBody)
			if len(snip) > 300 {
				snip = snip[:300]
			}
			t.Logf("  snippet:\n%s", snip)
		}
	}

	result, chainErr := DefaultChain().Verify(ctx, target, fp, Credentials{Username: user, Password: pass})
	t.Logf("chain verified=%v strategy=%q err=%v", result.Verified, result.Strategy, chainErr)
}
