//go:build windows

package agentapp

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// The uninstall-guard hash lives under HKLM (admin-writable only), so it
// survives agent config/enroll rewrites and cannot be cleared by a standard
// user. It is NOT a secret store — a determined admin can delete it (or the
// service) directly; it exists to stop casual/accidental uninstall.
const (
	uninstallGuardRegPath  = `SOFTWARE\Breeze`
	uninstallGuardRegValue = "UninstallGuardHash"
)

// storeUninstallGuard writes the "saltHex:hashHex" value under HKLM\SOFTWARE\Breeze.
func storeUninstallGuard(hash string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, uninstallGuardRegPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry key for write (run as Administrator): %w", err)
	}
	defer k.Close()
	if err := k.SetStringValue(uninstallGuardRegValue, hash); err != nil {
		return fmt.Errorf("write uninstall guard: %w", err)
	}
	return nil
}

// readUninstallGuard returns the stored hash and whether one is set. A missing
// key/value means no guard is configured (found=false, err=nil).
func readUninstallGuard() (hash string, found bool, err error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallGuardRegPath, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("open registry key: %w", err)
	}
	defer k.Close()
	v, _, err := k.GetStringValue(uninstallGuardRegValue)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read uninstall guard: %w", err)
	}
	if v == "" {
		return "", false, nil
	}
	return v, true, nil
}

// clearUninstallGuard removes the stored value. A missing value is not an error.
func clearUninstallGuard() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallGuardRegPath, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open registry key for clear: %w", err)
	}
	defer k.Close()
	if err := k.DeleteValue(uninstallGuardRegValue); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("delete uninstall guard: %w", err)
	}
	return nil
}
