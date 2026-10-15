//go:build !windows

package gatewayauth

// protectSecret keeps the authorization secret as-is on platforms without a
// user key store binding. The configuration file is written 0600, so the
// secret stays protected by file permissions alone; on Windows DPAPI seals it
// as well. See AGENTS.md for the threat model of the gateway authorization
// gate (deterrence, not a security boundary).
func protectSecret(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, errEmptySecret
	}
	return append([]byte(nil), plain...), nil
}

// unprotectSecret reverses protectSecret on platforms without a key store.
func unprotectSecret(stored []byte) ([]byte, error) {
	if len(stored) == 0 {
		return nil, errEmptySecret
	}
	return append([]byte(nil), stored...), nil
}
