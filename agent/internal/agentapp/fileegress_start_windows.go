//go:build windows

package agentapp

import (
	"context"

	"github.com/breeze-rmm/agent/internal/fileegress"
	"github.com/breeze-rmm/agent/internal/heartbeat"
	"github.com/breeze-rmm/agent/internal/privilege"
)

// startFileEgress subscribes to Microsoft-Windows-Kernel-File create events and
// reports files landing on removable/network egress surfaces via
// hb.SubmitFileEgressEvents. Non-fatal on init failure: the agent stays up, we
// just don't get file-egress detection. Mirrors startETWLua's privilege-first
// ordering so an unprivileged process never opens the real-time ETW session.
//
// The monitor self-gates on the heartbeat-delivered policy (hb.FileEgressConfig
// -> Enabled), so it is safe to start unconditionally on a privileged host; it
// stays idle until an enabled file_egress_policies row reaches this device.
//
// Returns a channel that closes after the monitor goroutine exits (via
// ctx.Done() in shutdownAgent), or immediately if init is skipped/failed.
func startFileEgress(ctx context.Context, hb *heartbeat.Heartbeat) <-chan struct{} {
	done := make(chan struct{})

	if !privilege.IsRunningAsRoot() {
		log.Info("fileegress disabled: agent not running as Administrator")
		close(done)
		return done
	}

	sub, err := fileegress.NewSubscriber(hb)
	if err != nil {
		log.Warn("fileegress subscriber init failed; file-egress detection disabled", "error", err.Error())
		close(done)
		return done
	}
	go func() {
		defer close(done)
		if err := fileegress.Start(ctx, sub, hb); err != nil {
			log.Warn("fileegress Start returned error", "error", err.Error())
		}
	}()
	return done
}
