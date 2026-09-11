//go:build !windows

package agentapp

import (
	"context"

	"github.com/breeze-rmm/agent/internal/heartbeat"
)

// startFileEgress is a no-op on non-Windows platforms. The Linux (fanotify)
// capture is a later wave; until then non-Windows agents run no file-egress
// monitor. Returns an already-closed channel so callers can range it for join
// semantics regardless of platform (mirrors etwlua_start_other.go).
func startFileEgress(_ context.Context, _ *heartbeat.Heartbeat) <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}
