//go:build !windows && !linux

package agentapp

import (
	"context"

	"github.com/breeze-rmm/agent/internal/heartbeat"
)

// startFileEgress is a no-op on platforms without a capture backend (macOS and
// the rest). Windows uses ETW (fileegress_start_windows.go) and Linux uses
// fanotify (fileegress_start_linux.go). Returns an already-closed channel so
// callers can range it for join semantics regardless of platform (mirrors
// etwlua_start_other.go).
func startFileEgress(_ context.Context, _ *heartbeat.Heartbeat) <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}
