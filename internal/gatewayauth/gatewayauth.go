// Package gatewayauth verifies that the operator of a NetWarden install also
// controls the network's gateway router. Privileged operation stays locked
// until a router adapter accepts the operator's gateway credentials, or the
// operator explicitly accepts an unverified session on gateways no adapter can
// authenticate against.
package gatewayauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Credentials are the gateway administrator login entered by the operator.
type Credentials struct {
	Username string
	Password string
}

// Valid reports whether the credentials can be offered to a router. Passwords
// are always required; usernames stay optional because several consumer
// gateways authenticate with a password alone.
func (c Credentials) Valid() error {
	if strings.TrimSpace(c.Password) == "" {
		return errors.New("the router password is required")
	}
	return nil
}

// Target identifies the gateway being authorized.
type Target struct {
	IP      string // default gateway address
	LocalIP string // local address used to reach it
	MAC     string // gateway hardware address when known
	Port    string // optional port override; empty means the scheme default
}

// Fingerprint is the evidence collected from the gateway before a verifier is
// selected. It is produced by Probe and passed to every verifier so adapters
// never have to re-fetch the login page.
type Fingerprint struct {
	Reachable bool
	Status    int
	Scheme    string // "http" or "https"
	Header    http.Header
	Body      string
}

// Challenge returns the gateway's HTTP authentication challenge, if any.
func (fp Fingerprint) Challenge() string {
	if fp.Header == nil {
		return ""
	}
	return fp.Header.Get("WWW-Authenticate")
}

// BodyContains reports whether the probed page contains a marker,
// case-insensitively.
func (fp Fingerprint) BodyContains(marker string) bool {
	return strings.Contains(strings.ToLower(fp.Body), strings.ToLower(marker))
}

// BodyContainsAny reports whether the probed page contains any marker.
func (fp Fingerprint) BodyContainsAny(markers ...string) bool {
	for _, marker := range markers {
		if fp.BodyContains(marker) {
			return true
		}
	}
	return false
}

var (
	// ErrUnreachable means the gateway could not be contacted at all.
	ErrUnreachable = errors.New("gateway is unreachable")
	// ErrNoAdapter means no verifier recognizes this gateway, so only an
	// explicitly unverified session is possible.
	ErrNoAdapter = errors.New("no router adapter matches this gateway")
	// ErrRejected means a matching verifier rejected the credentials.
	ErrRejected = errors.New("the router rejected the credentials")

	// errEmptySecret guards the secret codec against degenerate input.
	errEmptySecret = errors.New("empty authorization secret")
)

// Result describes an outcome of a verification attempt.
type Result struct {
	Verified bool   `json:"verified"`
	Strategy string `json:"strategy"`
	Detail   string `json:"detail,omitempty"`
}

// Verifier authenticates against one router family. Match decides whether the
// verifier understands the gateway; Verify performs exactly one credential
// attempt so a wrong password can never lock a router out through retries.
type Verifier interface {
	Name() string
	UsernameRequired() bool
	Match(Fingerprint) bool
	Verify(ctx context.Context, target Target, fp Fingerprint, creds Credentials) (Result, error)
}

// Chain is an ordered set of verifiers tried against a fingerprint.
type Chain struct {
	verifiers []Verifier
}

// NewChain returns a chain over the supplied verifiers, in priority order.
func NewChain(verifiers ...Verifier) *Chain { return &Chain{verifiers: verifiers} }

// DefaultChain returns every adapter NetWarden ships: protocol-level HTTP
// authentication first, then vendor form logins.
func DefaultChain() *Chain {
	return NewChain(
		&BasicVerifier{},
		&DigestVerifier{},
		&HuaweiVerifier{},
		&MikroTikVerifier{},
		&OpenWrtVerifier{},
		&ASUSVerifier{},
	)
}

// Verifiers exposes the ordered adapters of this chain.
func (c *Chain) Verifiers() []Verifier { return c.verifiers }

// Matching returns the verifiers that recognize the gateway.
func (c *Chain) Matching(fp Fingerprint) []Verifier {
	matching := make([]Verifier, 0, len(c.verifiers))
	for _, verifier := range c.verifiers {
		if verifier.Match(fp) {
			matching = append(matching, verifier)
		}
	}
	return matching
}

// AdapterName names the first adapter that recognizes the gateway, or "" when
// none does.
func (c *Chain) AdapterName(fp Fingerprint) string {
	for _, verifier := range c.verifiers {
		if verifier.Match(fp) {
			return verifier.Name()
		}
	}
	return ""
}

// UsernameRequired reports whether any matching adapter needs a username.
func (c *Chain) UsernameRequired(fp Fingerprint) bool {
	for _, verifier := range c.verifiers {
		if verifier.Match(fp) && verifier.UsernameRequired() {
			return true
		}
	}
	return false
}

// AdapterNames lists every adapter this build ships.
func (c *Chain) AdapterNames() []string {
	names := make([]string, 0, len(c.verifiers))
	for _, verifier := range c.verifiers {
		names = append(names, verifier.Name())
	}
	return names
}

// Verify tries each matching adapter exactly once. ErrNoAdapter is returned
// when nothing matches, ErrRejected (carrying per-adapter detail) when every
// matching adapter refused the credentials.
func (c *Chain) Verify(ctx context.Context, target Target, fp Fingerprint, creds Credentials) (Result, error) {
	matching := c.Matching(fp)
	if len(matching) == 0 {
		return Result{}, ErrNoAdapter
	}
	details := make([]string, 0, len(matching))
	for _, verifier := range matching {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		result, err := verifier.Verify(ctx, target, fp, creds)
		if err == nil && result.Verified {
			return result, nil
		}
		name := verifier.Name()
		if err == nil {
			err = errors.New("verification failed")
		}
		if errors.Is(err, ErrUnreachable) {
			return Result{}, err
		}
		details = append(details, fmt.Sprintf("%s: %v", name, err))
	}
	return Result{Detail: strings.Join(details, "; ")}, fmt.Errorf("%w (%s)", ErrRejected, strings.Join(details, "; "))
}

// AdapterNames lists the adapters of the default chain.
func AdapterNames() []string { return DefaultChain().AdapterNames() }
