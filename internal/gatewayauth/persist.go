package gatewayauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"

	"github.com/amdzy/NetWarden/internal/config"
)

// NewRecord persists an authorization decision. The password is never stored:
// only a random secret (protected by the OS user key store where available)
// and an HMAC proof binding that secret to the gateway identity.
func NewRecord(target Target, strategy string, verified bool, now time.Time) (config.GatewayAuthRecord, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return config.GatewayAuthRecord{}, err
	}
	protected, err := protectSecret(secret)
	if err != nil {
		return config.GatewayAuthRecord{}, err
	}
	return config.GatewayAuthRecord{
		AuthorizedAt: now.UTC(),
		GatewayIP:    target.IP,
		LocalIP:      target.LocalIP,
		GatewayMAC:   strings.ToLower(target.MAC),
		Strategy:     strategy,
		Verified:     verified,
		Secret:       base64.StdEncoding.EncodeToString(protected),
		Proof:        base64.StdEncoding.EncodeToString(computeProof(secret, identity(target))),
	}, nil
}

// Matches reports whether a stored authorization was issued for the gateway we
// are looking at now. The gateway MAC participates when both sides know it;
// the local address is deliberately excluded so an ordinary DHCP renewal does
// not lock the operator out.
func Matches(record *config.GatewayAuthRecord, target Target) bool {
	if record == nil || record.GatewayIP == "" || target.IP == "" {
		return false
	}
	if !strings.EqualFold(record.GatewayIP, target.IP) {
		return false
	}
	if record.GatewayMAC != "" && target.MAC != "" && !strings.EqualFold(record.GatewayMAC, target.MAC) {
		return false
	}
	return true
}

// CheckProof re-derives the stored proof. A forged or edited record fails here
// even when the gateway identity matches.
func CheckProof(record *config.GatewayAuthRecord, target Target) bool {
	if record == nil || record.Secret == "" || record.Proof == "" {
		return false
	}
	protected, err := base64.StdEncoding.DecodeString(record.Secret)
	if err != nil {
		return false
	}
	secret, err := unprotectSecret(protected)
	if err != nil || len(secret) == 0 {
		return false
	}
	stored, err := base64.StdEncoding.DecodeString(record.Proof)
	if err != nil {
		return false
	}
	return hmac.Equal(stored, computeProof(secret, identity(target)))
}

func identity(target Target) []byte {
	return []byte(strings.ToLower(target.IP) + "|" + strings.ToLower(target.MAC))
}

func computeProof(secret, identity []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(identity)
	return mac.Sum(nil)
}
