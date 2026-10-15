package gatewayauth

import (
	"context"
	"crypto/md5" //nolint:gosec // MD5 is mandated by RFC 7616 digest authentication
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"regexp"
	"strings"
)

// DigestVerifier handles gateways that answer with an RFC 7616 Digest
// challenge (MD5 or SHA-256, qop=auth). The password never travels on the
// wire: only the challenge-response derived from it.
type DigestVerifier struct{}

// Name implements Verifier.
func (v *DigestVerifier) Name() string { return "http-digest" }

// UsernameRequired implements Verifier.
func (v *DigestVerifier) UsernameRequired() bool { return true }

// Match implements Verifier.
func (v *DigestVerifier) Match(fp Fingerprint) bool {
	return challengeHasScheme(fp.Challenge(), "digest")
}

type digestChallenge struct {
	realm     string
	nonce     string
	qop       string
	opaque    string
	algorithm string
}

var digestPairRE = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9_-]*)=("(?:[^"\\]|\\.)*"|[^,]*)`)

// parseDigestChallenge extracts the parameters of a Digest challenge.
func parseDigestChallenge(header string) (digestChallenge, bool) {
	lower := strings.ToLower(header)
	start := strings.Index(lower, "digest ")
	if start < 0 {
		return digestChallenge{}, false
	}
	spec := header[start+len("digest "):]
	// A header may pack several challenges; stop at the next scheme.
	if stop := strings.Index(strings.ToLower(spec), ", basic"); stop >= 0 {
		spec = spec[:stop]
	}
	if stop := strings.Index(strings.ToLower(spec), ", negotiate"); stop >= 0 {
		spec = spec[:stop]
	}
	parsed := digestChallenge{algorithm: "MD5"}
	found := false
	for _, match := range digestPairRE.FindAllStringSubmatch(spec, -1) {
		if len(match) < 3 {
			continue
		}
		value := strings.Trim(match[2], `"`)
		switch strings.ToLower(match[1]) {
		case "realm":
			parsed.realm, found = value, true
		case "nonce":
			parsed.nonce = value
		case "qop":
			parsed.qop = value
		case "opaque":
			parsed.opaque = value
		case "algorithm":
			parsed.algorithm = value
		}
	}
	if !found || parsed.nonce == "" {
		return digestChallenge{}, false
	}
	return parsed, true
}

func digestHash(algorithm string) (func() hash.Hash, bool) {
	switch strings.TrimSuffix(strings.ToLower(algorithm), "-sess") {
	case "md5":
		return md5.New, true
	case "sha-256":
		return sha256.New, true
	default:
		return nil, false
	}
}

func digestHex(newHash func() hash.Hash, parts ...string) string {
	writer := newHash()
	for index, part := range parts {
		if index > 0 {
			writer.Write([]byte(":"))
		}
		writer.Write([]byte(part))
	}
	return hex.EncodeToString(writer.Sum(nil))
}

// buildDigestAuthorization produces the Authorization header for one request.
func buildDigestAuthorization(ch digestChallenge, method, uri, username, password string) (string, error) {
	newHash, ok := digestHash(ch.algorithm)
	if !ok {
		return "", fmt.Errorf("unsupported digest algorithm %q", ch.algorithm)
	}
	qop := ""
	for _, option := range strings.Split(ch.qop, ",") {
		if strings.TrimSpace(option) == "auth" {
			qop = "auth"
			break
		}
	}
	if ch.qop != "" && qop == "" {
		return "", fmt.Errorf("gateway only offers unsupported quality of protection %q", ch.qop)
	}

	nonceCount := "00000001"
	cnonceBytes := make([]byte, 8)
	if _, err := rand.Read(cnonceBytes); err != nil {
		return "", err
	}
	cnonce := hex.EncodeToString(cnonceBytes)

	ha1 := digestHex(newHash, username, ch.realm, password)
	if strings.HasSuffix(strings.ToLower(ch.algorithm), "-sess") {
		ha1 = digestHex(newHash, ha1, ch.nonce, cnonce)
	}
	ha2 := digestHex(newHash, method, uri)

	var response string
	if qop == "auth" {
		response = digestHex(newHash, ha1, ch.nonce, nonceCount, cnonce, qop, ha2)
	} else {
		response = digestHex(newHash, ha1, ch.nonce, ha2)
	}

	parts := []string{
		`username="` + escapeQuotes(username) + `"`,
		`realm="` + escapeQuotes(ch.realm) + `"`,
		`nonce="` + escapeQuotes(ch.nonce) + `"`,
		`uri="` + escapeQuotes(uri) + `"`,
		`response="` + response + `"`,
		`algorithm=` + ch.algorithm,
	}
	if qop == "auth" {
		parts = append(parts, "qop=auth", "nc="+nonceCount, "cnonce=\""+cnonce+"\"")
	}
	if ch.opaque != "" {
		parts = append(parts, `opaque="`+escapeQuotes(ch.opaque)+`"`)
	}
	return "Digest " + strings.Join(parts, ", "), nil
}

func escapeQuotes(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

// Verify implements Verifier with a single challenge-response round trip.
func (v *DigestVerifier) Verify(ctx context.Context, target Target, fp Fingerprint, creds Credentials) (Result, error) {
	client := newPinnedClient(target)
	challenge, ok := parseDigestChallenge(fp.Challenge())
	if !ok {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, gatewayURL(fp.Scheme, target, "/"), nil)
		if err != nil {
			return Result{}, err
		}
		req.Header.Set("User-Agent", userAgent)
		resp, _, err := doRequest(ctx, client, req)
		if err != nil {
			return Result{}, fmt.Errorf("%w: %v", ErrUnreachable, err)
		}
		if resp.Body != nil {
			resp.Body.Close()
		}
		if challenge, ok = parseDigestChallenge(resp.Header.Get("WWW-Authenticate")); !ok {
			return Result{}, errors.New("gateway issued no digest challenge")
		}
	}

	uri := "/"
	authorization, err := buildDigestAuthorization(challenge, http.MethodGet, uri, creds.Username, creds.Password)
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gatewayURL(fp.Scheme, target, uri), nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Authorization", authorization)
	resp, _, err := doRequest(ctx, client, req)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	if resp.Body != nil {
		resp.Body.Close()
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return Result{}, fmt.Errorf("credentials refused with status %d", resp.StatusCode)
	case resp.StatusCode >= 400:
		return Result{}, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return Result{Verified: true, Strategy: v.Name()}, nil
}
