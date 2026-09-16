//go:build linux

package fileegress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fanotifySubscriber watches removable and network-share mounts for finished
// writes (FAN_CLOSE_WRITE) — a file landing on a USB stick or an SMB/NFS share
// (wave-2a, the analogue of the Windows Kernel-File Create capture). It also
// drives wave-2b (read→upload correlation): since fanotify has no network side,
// that runs as a /proc poller (uploadPollLoop in upload_linux.go) feeding the
// shared correlator, rather than the Windows ETW network/DNS streams.
type fanotifySubscriber struct {
	fd     int
	events chan Event
	poster Poster
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu     sync.Mutex
	marked map[string]string // mountPoint -> egressType (already FAN_MARK'd)

	// wave-2b: read→upload correlation, fed by the /proc poller in
	// upload_linux.go (no system-wide fanotify FAN_OPEN — see uploadPollLoop).
	corr     *correlator
	connSeen map[string]time.Time // "pid|ip|port" -> last onConnect, to avoid re-firing
}

const fanotifyEventBufSize = 16 * 1024

// NewSubscriber creates the Linux fanotify-backed capture. Requires root
// (CAP_SYS_ADMIN); Start() also gates on privilege, so an unprivileged agent
// never reaches here.
func NewSubscriber(poster Poster) (Subscriber, error) {
	fd, err := unix.FanotifyInit(
		unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK,
		unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC,
	)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &fanotifySubscriber{
		fd:       fd,
		events:   make(chan Event, 256),
		poster:   poster,
		ctx:      ctx,
		cancel:   cancel,
		marked:   make(map[string]string),
		corr:     newCorrelator(poster.FileEgressConfig()),
		connSeen: make(map[string]time.Time),
	}
	// Mark whatever egress mounts exist now; markLoop picks up later plug-ins.
	s.refreshMarks()
	s.wg.Add(3)
	go s.readLoop()       // wave-2a: removable/network-share writes (fanotify)
	go s.markLoop()       // re-scan mounts for USB plug-ins
	go s.uploadPollLoop() // wave-2b: read→upload correlation (/proc poller)
	return s, nil
}

func (s *fanotifySubscriber) Events() <-chan Event { return s.events }

func (s *fanotifySubscriber) Stop() {
	s.cancel()
	// Closing the fd unblocks any in-flight read; the poll loop also wakes on
	// its own timeout and observes ctx.Done.
	_ = unix.Close(s.fd)
	s.wg.Wait()
	close(s.events)
}

// refreshMarks scans mounts and adds a FAN_MARK_MOUNT watch on any removable or
// network-share mount not already marked. FAN_CLOSE_WRITE fires when a writable
// descriptor is closed — the "a file finished landing here" signal.
func (s *fanotifySubscriber) refreshMarks() {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		log.Debug("fileegress: open mountinfo failed", "error", err.Error())
		return
	}
	defer f.Close()
	mounts := parseMountinfo(f)

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range mounts {
		if _, done := s.marked[m.mountPoint]; done {
			continue
		}
		egress, ok := classifyMount(m, blockDeviceRemovable)
		if !ok {
			continue
		}
		if err := unix.FanotifyMark(s.fd, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT,
			unix.FAN_CLOSE_WRITE, unix.AT_FDCWD, m.mountPoint); err != nil {
			log.Debug("fileegress: fanotify_mark failed", "mount", m.mountPoint, "error", err.Error())
			continue
		}
		s.marked[m.mountPoint] = egress
		log.Info("fileegress: watching egress mount", "mount", m.mountPoint, "type", egress, "fs", m.fsType)
	}
}

// markLoop re-scans mounts so a USB stick plugged in after start is watched.
func (s *fanotifySubscriber) markLoop() {
	defer s.wg.Done()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			s.refreshMarks()
		}
	}
}

func (s *fanotifySubscriber) readLoop() {
	defer s.wg.Done()
	buf := make([]byte, fanotifyEventBufSize)
	pfd := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}
	for {
		if s.ctx.Err() != nil {
			return
		}
		n, err := unix.Poll(pfd, 500)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return // fd closed on Stop
		}
		if n == 0 {
			continue // timeout — loop back to re-check ctx
		}
		nr, err := unix.Read(s.fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			return
		}
		if nr <= 0 {
			continue
		}
		s.parseEvents(buf[:nr])
	}
}

// metaSize is sizeof(struct fanotify_event_metadata).
var metaSize = int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))

func (s *fanotifySubscriber) parseEvents(buf []byte) {
	for len(buf) >= metaSize {
		meta := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[0]))
		evLen := int(meta.Event_len)
		if evLen < metaSize || evLen > len(buf) {
			return // truncated / malformed batch
		}
		if meta.Vers == unix.FANOTIFY_METADATA_VERSION && meta.Fd >= 0 {
			s.handleFd(int(meta.Fd), int(meta.Pid))
		} else if meta.Fd >= 0 {
			_ = unix.Close(int(meta.Fd))
		}
		buf = buf[evLen:]
	}
}

// handleFd resolves the file path + size behind an event fd, classifies it,
// applies the active policy, and emits an Event. It always closes the fd.
func (s *fanotifySubscriber) handleFd(fd, pid int) {
	defer unix.Close(fd)

	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil || path == "" {
		return
	}
	// A deleted file resolves to "<path> (deleted)"; drop the marker.
	path = strings.TrimSuffix(path, " (deleted)")

	egress, mount := s.classifyPath(path)
	if egress == "" {
		return // not under a watched egress mount (shouldn't happen)
	}

	var size int64
	var st unix.Stat_t
	if unix.Fstat(fd, &st) == nil {
		size = st.Size
	}

	cfg := s.poster.FileEgressConfig()
	if !cfg.ShouldReport(egress, path, size) {
		return
	}

	details := map[string]any{
		"path":       path,
		"destVolume": mount,
		"pid":        pid,
		"sizeBytes":  size,
	}
	if proc := processName(pid); proc != "" {
		details["process"] = proc
	}

	select {
	case s.events <- Event{
		EventID:    egressEventID(egress, path, mount),
		EgressType: egress,
		Details:    details,
		OccurredAt: time.Now().UTC(),
	}:
	case <-s.ctx.Done():
	default:
		log.Debug("fileegress: event channel full, dropping", "path", path)
	}
}

// classifyPath finds the watched mount that is the longest path-prefix of the
// event path, returning its egress type and mount point.
func (s *fanotifySubscriber) classifyPath(path string) (egressType, mount string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mounts := make([]string, 0, len(s.marked))
	for mp := range s.marked {
		if mp == path || strings.HasPrefix(path, strings.TrimSuffix(mp, "/")+"/") {
			mounts = append(mounts, mp)
		}
	}
	if len(mounts) == 0 {
		return "", ""
	}
	// Longest mount point wins (most specific), e.g. /media over /.
	sort.Slice(mounts, func(i, j int) bool { return len(mounts[i]) > len(mounts[j]) })
	return s.marked[mounts[0]], mounts[0]
}

// processName reads the short process name for a pid; "" if unavailable.
func processName(pid int) string {
	if pid <= 0 {
		return ""
	}
	if data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm")); err == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}

// egressEventID is the agent-side idempotency key. A 30s dedupe window in the
// core loop collapses the burst of CLOSE_WRITE events a single copy can emit.
func egressEventID(egressType, path, mount string) string {
	bucket := time.Now().UTC().Truncate(30 * time.Second).Unix()
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%d", egressType, path, mount, bucket)))
	return hex.EncodeToString(sum[:])[:32]
}
