package agentapp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Uninstall guard: an optional password that must be supplied to
// `service uninstall`. This is overt tamper-resistance for company-owned DLP
// hosts — it stops a casual/accidental uninstall, not a determined admin (who
// can still `sc delete` or run the documented nuke script). The stored value is
// "saltHex:sha256Hex" of salt||password. It lives in the registry (Windows),
// which is admin-writable only; strength is not the threat model (an attacker
// with the config/registry already has admin), so a salted SHA-256 is adequate.

const uninstallGuardSaltLen = 16

// hashUninstallPassword returns "saltHex:hashHex" for the given password.
func hashUninstallPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("uninstall password must not be empty")
	}
	salt := make([]byte, uninstallGuardSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	sum := sha256.Sum256(append(append([]byte{}, salt...), []byte(password)...))
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(sum[:]), nil
}

// verifyUninstallPassword reports whether password matches the stored
// "saltHex:hashHex" value, in constant time. A malformed stored value never
// matches.
func verifyUninstallPassword(stored, password string) bool {
	parts := strings.SplitN(stored, ":", 2)
	if len(parts) != 2 {
		return false
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	sum := sha256.Sum256(append(append([]byte{}, salt...), []byte(password)...))
	return subtle.ConstantTimeCompare(sum[:], want) == 1
}
