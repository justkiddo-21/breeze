// Package fileegress implements the agent-side file-egress (DLP) monitor.
//
// It watches for files leaving a company-owned machine via egress surfaces —
// removable/USB volumes, network shares, and (wave 2b) the "a process read a
// file then uploaded it" case — and reports each detection to the Breeze API.
//
// Shape mirrors internal/etwlua: a standing monitor started as `go Start(...)`
// from a platform-split wrapper in internal/agentapp, gated on privilege, with
// the OS-specific capture isolated behind the Subscriber interface. The core
// here is platform-agnostic and unit-tested; the Windows ETW capture lives in
// monitor_windows.go, and non-Windows builds get a no-op subscriber.
package fileegress

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/breeze-rmm/agent/internal/logging"
	"github.com/breeze-rmm/agent/internal/privilege"
)

var log = logging.L("fileegress")

// Egress surface classifications. These MUST match the server's
// file_egress_type enum (apps/api migration 2026-10-15-140006) and the agent
// ingest route's zod schema.
const (
	EgressRemovable    = "removable"
	EgressNetworkShare = "network_share"
	EgressAppUpload    = "app_upload"
)

// ErrNotPrivileged is returned by Start when the process lacks the SYSTEM/admin
// rights an ETW real-time session requires — a silent no-op is better than a
// noisy failure loop (mirrors etwlua).
var ErrNotPrivileged = errors.New("fileegress: process not running with admin/SYSTEM privileges; file-egress monitor skipped")

// Config is the per-device policy delivered on the heartbeat response under
// configUpdate["file_egress_settings"]. JSON tags match the server's
// FileEgressConfigUpdate (apps/api/src/routes/agents/helpers.ts).
type Config struct {
	Enabled            bool     `json:"enabled"`
	WatchRemovable     bool     `json:"watch_removable"`
	WatchNetworkShares bool     `json:"watch_network_shares"`
	WatchUploads       bool     `json:"watch_uploads"`
	// nil => the monitor uses its built-in default process list.
	UploadProcessWatchlist []string `json:"upload_process_watchlist"`
	IgnoreGlobs            []string `json:"ignore_globs"`
	MinFileSizeBytes       int64    `json:"min_file_size_bytes"`
}

// Event is one detected egress, sent to the server. JSON matches the ingest
// route's schema: { eventId?, egressType, details?, occurredAt }.
type Event struct {
	// EventID is an agent-side idempotency key; the server dedupes on
	// (org, device, eventId).
	EventID    string         `json:"eventId,omitempty"`
	EgressType string         `json:"egressType"`
	Details    map[string]any `json:"details,omitempty"`
	OccurredAt time.Time      `json:"occurredAt"`
}

// EventSubmission is the PUT body for /api/v1/agents/{id}/file-egress/events.
type EventSubmission struct {
	Events []Event `json:"events"`
}

// Poster is the agent-core dependency the monitor posts through. Implemented by
// *heartbeat.Heartbeat so this package never imports the heartbeat package
// (mirrors etwlua.HeartbeatPoster).
type Poster interface {
	// SubmitFileEgressEvents PUTs a batch; a non-nil error means the batch was
	// not accepted and should be retried.
	SubmitFileEgressEvents(events []Event) error
	// FileEgressConfig returns the currently active policy (zero value =
	// disabled) so the monitor can gate on the latest heartbeat config.
	FileEgressConfig() Config
}

// Subscriber is the OS-specific capture source. Windows returns an ETW-backed
// implementation; other platforms return a no-op whose channel never yields.
type Subscriber interface {
	Events() <-chan Event
	Stop()
}

const (
	flushInterval  = 5 * time.Second
	maxBatchSize   = 100
	maxPending     = 1000 // cap the retry buffer so a long API outage can't grow it unbounded
	dedupeWindow   = 30 * time.Second
	dedupeMaxKeys  = 4096
)

// ParseFileEgressConfig round-trips an untyped heartbeat config block into a
// typed Config (mirrors monitoring.ParseMonitorConfig). Returns ok=false on a
// malformed block so the caller leaves the previous config in place.
func ParseFileEgressConfig(raw any) (Config, bool) {
	var cfg Config
	data, err := json.Marshal(raw)
	if err != nil {
		log.Warn("fileegress: failed to marshal config", "error", err.Error())
		return cfg, false
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Warn("fileegress: failed to parse config", "error", err.Error())
		return cfg, false
	}
	return cfg, true
}

// ShouldReport applies the policy's surface toggles, minimum size, and ignore
// globs. Pure and unit-tested; the OS capture calls it before emitting.
func (c Config) ShouldReport(egressType, path string, sizeBytes int64) bool {
	if !c.Enabled {
		return false
	}
	switch egressType {
	case EgressRemovable:
		if !c.WatchRemovable {
			return false
		}
	case EgressNetworkShare:
		if !c.WatchNetworkShares {
			return false
		}
	case EgressAppUpload:
		if !c.WatchUploads {
			return false
		}
	default:
		return false
	}
	if sizeBytes > 0 && c.MinFileSizeBytes > 0 && sizeBytes < c.MinFileSizeBytes {
		return false
	}
	if matchesAnyGlob(path, c.IgnoreGlobs) {
		return false
	}
	return true
}

// matchesAnyGlob returns true if path (or its base name) matches any glob.
// A malformed pattern is ignored rather than treated as a match.
func matchesAnyGlob(path string, globs []string) bool {
	if len(globs) == 0 {
		return false
	}
	base := filepath.Base(path)
	lowerPath := strings.ToLower(filepath.ToSlash(path))
	for _, g := range globs {
		if g == "" {
			continue
		}
		lg := strings.ToLower(g)
		if ok, err := filepath.Match(lg, strings.ToLower(base)); err == nil && ok {
			return true
		}
		if ok, err := filepath.Match(lg, lowerPath); err == nil && ok {
			return true
		}
		// A bare substring/prefix pattern with no glob metacharacters: treat as
		// a path-contains match so an operator can ignore e.g. a temp dir.
		if !strings.ContainsAny(lg, "*?[") && strings.Contains(lowerPath, lg) {
			return true
		}
	}
	return false
}

// Start runs the monitor loop until ctx is cancelled or the subscriber's
// channel closes. It refuses to run unprivileged. Caller launches it as a
// goroutine (see internal/agentapp/fileegress_start_windows.go).
func Start(ctx context.Context, sub Subscriber, poster Poster) error {
	if !privilege.IsRunningAsRoot() {
		log.Warn(ErrNotPrivileged.Error())
		return ErrNotPrivileged
	}
	defer sub.Stop()

	log.Info("fileegress monitor started")

	dd := newDeduper(dedupeWindow, dedupeMaxKeys)
	pending := make([]Event, 0, maxBatchSize)

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(pending) == 0 {
			return
		}
		if err := poster.SubmitFileEgressEvents(pending); err != nil {
			log.Debug("fileegress: submit failed, will retry", "error", err.Error(), "pending", len(pending))
			// Keep the buffer for the next tick, but bound it: drop the oldest
			// on overflow so a prolonged outage can't grow memory without limit.
			if len(pending) > maxPending {
				pending = pending[len(pending)-maxPending:]
			}
			return
		}
		pending = pending[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			log.Info("fileegress monitor stopping")
			return nil
		case ev, ok := <-sub.Events():
			if !ok {
				flush()
				log.Warn("fileegress: subscriber channel closed; exiting loop")
				return nil
			}
			// Gate on the latest heartbeat-delivered config: the capture layer
			// may still be draining events from just before a disable.
			if !poster.FileEgressConfig().Enabled {
				continue
			}
			if ev.EventID != "" && !dd.allow(ev.EventID) {
				continue
			}
			pending = append(pending, ev)
			if len(pending) >= maxBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
			dd.prune()
		}
	}
}
