//go:build !windows

package agentapp

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/breeze-rmm/agent/internal/config"
)

// On non-Windows the guard hash lives in a root-only file under the config dir
// (/etc/breeze on Linux). enroll rewrites agent.yaml, not this file, so it
// survives re-enrollment. Same threat model as Windows: it stops a casual
// `service uninstall`, not a root user who can `systemctl`/`rm` directly.
func uninstallGuardPath() string {
	return filepath.Join(config.ConfigDir(), "uninstall-guard")
}

func storeUninstallGuard(hash string) error {
	dir := config.ConfigDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := os.WriteFile(uninstallGuardPath(), []byte(hash), 0o600); err != nil {
		return fmt.Errorf("write uninstall guard: %w", err)
	}
	return nil
}

func readUninstallGuard() (hash string, found bool, err error) {
	data, err := os.ReadFile(uninstallGuardPath())
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read uninstall guard: %w", err)
	}
	if len(data) == 0 {
		return "", false, nil
	}
	return string(data), true, nil
}

func clearUninstallGuard() error {
	if err := os.Remove(uninstallGuardPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove uninstall guard: %w", err)
	}
	return nil
}
