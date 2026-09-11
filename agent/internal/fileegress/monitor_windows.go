//go:build windows

package fileegress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
	log "github.com/breeze-rmm/agent/internal/logging"
)

// Microsoft-Windows-Kernel-File provider. The CREATE keyword (0x80) scopes the
// real-time session to file-create events, which carry the full FileName — so
// wave 2a detects "a file was created on an egress volume" without needing the
// FileObject->path rundown that Write/Read events (wave 2b) require.
const (
	kernelFileProviderGUID = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"
	kernelFileKeywordCreate = 0x80
	// Kernel-File "Create" event: carries FileName, CreateOptions, and the
	// issuing PID in the event header.
	kernelFileEventCreate = 12
	// verbose level so create events are delivered.
	traceLevelVerbose = 5

	sessionName    = "Breeze-FileEgress"
	eventChanDepth = 256
)

// NewSubscriber starts a Breeze-FileEgress ETW real-time session subscribed to
// Kernel-File create events, classifies each created path's volume, and emits
// an Event for writes landing on a removable or network surface. The poster is
// consulted for the live policy (ShouldReport) so config changes take effect
// without restarting the session.
//
// CI/Windows-spike validation points (cannot be exercised on the Linux build
// host): the golang-etw property getter name (GetPropertyString), the Provider
// keyword/level field names, and that Kernel-File FileName is delivered as an
// NT device path the classifier expects.
func NewSubscriber(poster Poster) (Subscriber, error) {
	session := etw.NewRealTimeSession(sessionName)

	provider, err := etw.ParseProvider(kernelFileProviderGUID)
	if err != nil {
		return nil, fmt.Errorf("fileegress: parse Kernel-File provider: %w", err)
	}
	provider.EnableLevel = traceLevelVerbose
	provider.MatchAnyKeyword = kernelFileKeywordCreate

	if err := session.EnableProvider(provider); err != nil {
		_ = session.Stop()
		return nil, fmt.Errorf("fileegress: enable Kernel-File provider: %w", err)
	}

	s := &etwSubscriber{
		poster:     poster,
		session:    session,
		classifier: newDriveClassifier(),
		events:     make(chan Event, eventChanDepth),
		doneCh:     make(chan struct{}),
	}
	// NewRealTimeConsumer panics on a nil parent context (see etwlua).
	s.consumer = etw.NewRealTimeConsumer(context.Background()).FromSessions(session)
	s.consumer.EventRecordHelperCallback = s.onEvent

	go s.run()
	return s, nil
}

type etwSubscriber struct {
	poster     Poster
	session    *etw.RealTimeSession
	consumer   *etw.Consumer
	classifier *driveClassifier
	events     chan Event
	doneCh     chan struct{}
	stopOnce   sync.Once
}

func (s *etwSubscriber) Events() <-chan Event { return s.events }

func (s *etwSubscriber) run() {
	defer close(s.doneCh)
	if err := s.consumer.Start(); err != nil {
		log.Error("fileegress: ETW consumer start failed", "error", err.Error())
		return
	}
	// Drain the library's own event channel; our work happens in the callback.
	for range s.consumer.Events {
	}
}

func (s *etwSubscriber) Stop() {
	s.stopOnce.Do(func() {
		if err := s.consumer.Stop(); err != nil {
			log.Warn("fileegress: ETW consumer stop", "error", err.Error())
		}
		if err := s.session.Stop(); err != nil {
			log.Warn("fileegress: ETW session stop", "error", err.Error())
		}
		<-s.doneCh
	})
}

// onEvent is the per-event callback. It must be cheap: Kernel-File is a
// high-volume provider even scoped to CREATE, so we Skip() anything that isn't
// a create on an egress surface before doing any allocation-heavy work.
func (s *etwSubscriber) onEvent(h *etw.EventRecordHelper) error {
	if h.EventID() != kernelFileEventCreate {
		h.Skip()
		return nil
	}

	ntPath, err := h.GetPropertyString("FileName")
	if err != nil || ntPath == "" {
		h.Skip()
		return nil
	}

	egressType, destVolume := s.classifier.classify(ntPath)
	if egressType == "" {
		h.Skip()
		return nil
	}

	// Full policy filter (surface toggles, min-size — size unknown at create
	// time so 0, ignore globs) against the live config.
	if !s.poster.FileEgressConfig().ShouldReport(egressType, ntPath, 0) {
		h.Skip()
		return nil
	}

	pid := h.EventRec.EventHeader.ProcessId
	procPath := processImageName(pid)

	now := time.Now().UTC()
	ev := Event{
		EventID:    egressEventID(ntPath, pid, now),
		EgressType: egressType,
		OccurredAt: now,
		Details: map[string]any{
			"filePath":    ntPath,
			"destVolume":  destVolume,
			"processId":   pid,
			"processPath": procPath,
		},
	}
	h.Skip()

	select {
	case s.events <- ev:
	default:
		log.Warn("fileegress: event channel full, dropping", "path", ntPath)
	}
	return nil
}

// egressEventID is a stable idempotency key for one egress. Bucketed to the
// minute so the same file copy retried within the dedupe window collapses,
// while a genuinely repeated copy later gets a fresh id.
func egressEventID(path string, pid uint32, t time.Time) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", path, pid, t.Unix()/60)))
	return hex.EncodeToString(sum[:16])
}
