package gatewayauth

import (
	"context"
	"errors"
	"testing"
)

type fakeVerifier struct {
	name     string
	match    bool
	verified bool
	err      error
	calls    *int
}

func (v *fakeVerifier) Name() string           { return v.name }
func (v *fakeVerifier) UsernameRequired() bool { return true }
func (v *fakeVerifier) Match(Fingerprint) bool { return v.match }

func (v *fakeVerifier) Verify(context.Context, Target, Fingerprint, Credentials) (Result, error) {
	if v.calls != nil {
		*v.calls++
	}
	if v.err != nil {
		return Result{}, v.err
	}
	return Result{Verified: v.verified, Strategy: v.name}, nil
}

func TestDefaultChainShipsEveryAdapter(t *testing.T) {
	want := []string{"http-basic", "http-digest", "huawei-ont", "mikrotik-routeros-api", "openwrt-luci", "asuswrt"}
	got := AdapterNames()
	if len(got) != len(want) {
		t.Fatalf("adapters = %v, want %v", got, want)
	}
	for index, name := range want {
		if got[index] != name {
			t.Fatalf("adapters[%d] = %q, want %q (full list %v)", index, got[index], name, got)
		}
	}
}

func TestVerifyWithoutMatchingAdapterIsSoftMode(t *testing.T) {
	chain := NewChain(&fakeVerifier{name: "never", match: false})
	_, err := chain.Verify(t.Context(), Target{IP: "192.168.1.1"}, Fingerprint{}, credentials())
	if !errors.Is(err, ErrNoAdapter) {
		t.Fatalf("got %v, want ErrNoAdapter", err)
	}
}

func TestVerifyRejectsWithPerAdapterDetail(t *testing.T) {
	chain := NewChain(&fakeVerifier{name: "vendor-x", match: true, err: errors.New("login form still served")})
	result, err := chain.Verify(t.Context(), Target{IP: "192.168.1.1"}, Fingerprint{}, credentials())
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("got %v, want ErrRejected", err)
	}
	if result.Verified {
		t.Fatal("a rejected chain must not report verification")
	}
	if !containsDetail(err, "vendor-x: login form still served") {
		t.Fatalf("detail missing from %v", err)
	}
}

func TestVerifyStopsChainOnUnreachableGateway(t *testing.T) {
	secondCalls := 0
	chain := NewChain(
		&fakeVerifier{name: "first", match: true, err: ErrUnreachable},
		&fakeVerifier{name: "second", match: true, verified: true, calls: &secondCalls},
	)
	_, err := chain.Verify(t.Context(), Target{IP: "192.168.1.1"}, Fingerprint{}, credentials())
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
	if secondCalls != 0 {
		t.Fatalf("second adapter was tried %d times after an unreachable gateway", secondCalls)
	}
}

func TestVerifyReturnsFirstSuccessAndSkipsLaterAdapters(t *testing.T) {
	secondCalls := 0
	chain := NewChain(
		&fakeVerifier{name: "first", match: true, verified: true},
		&fakeVerifier{name: "second", match: true, verified: true, calls: &secondCalls},
	)
	result, err := chain.Verify(t.Context(), Target{IP: "192.168.1.1"}, Fingerprint{}, credentials())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified || result.Strategy != "first" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if secondCalls != 0 {
		t.Fatalf("second adapter called %d times after success", secondCalls)
	}
}

func TestMatchingAdaptersHonourMatch(t *testing.T) {
	chain := NewChain(
		&fakeVerifier{name: "yes", match: true},
		&fakeVerifier{name: "no", match: false},
	)
	if got := len(chain.Matching(Fingerprint{})); got != 1 {
		t.Fatalf("matching adapters = %d, want 1", got)
	}
	if name := chain.AdapterName(Fingerprint{}); name != "yes" {
		t.Fatalf("AdapterName = %q, want yes", name)
	}
	if chain.UsernameRequired(Fingerprint{}) != true {
		t.Fatal("UsernameRequired should be true when a matching adapter needs a user")
	}
}

func TestCredentialsRequirePasswordOnly(t *testing.T) {
	if err := (Credentials{Username: "", Password: "x"}).Valid(); err != nil {
		t.Fatalf("password-only credentials should be valid: %v", err)
	}
	if err := (Credentials{Username: "admin", Password: " "}).Valid(); err == nil {
		t.Fatal("blank password must be refused")
	}
}
