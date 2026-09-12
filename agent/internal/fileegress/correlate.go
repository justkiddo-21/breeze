package fileegress

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Wave 2b: read→upload correlation.
//
// Architecture (connect-driven, per the design review): we do NOT subscribe to
// the firehose of Kernel-File Read events. Instead:
//   - Kernel-File CREATE events for WATCHLISTED processes feed a bounded,
//     time-windowed per-PID "recent interesting opens" buffer (Create carries
//     PID + FileName, so no FileObject→path map and no reuse-race).
//   - Microsoft-Windows-DNS-Client events feed a per-PID resolvedIP→domain cache
//     (so a TLS destination IP can be labelled with the real service name — you
//     cannot derive "zalo.me" from a shared-CDN IP).
//   - A Kernel-Network OUTBOUND CONNECT from a watchlisted process to an
//     EXTERNAL address, when that process has a recent interesting open, emits
//     one app_upload Event correlating the file + process + destination.
//
// The correlator is shared across two ETW consumer callback threads (file +
// network/dns sessions), so every method takes the mutex. It owns its own
// deduper (used only under the lock). It NEVER touches the Start goroutine's
// deduper. Finished Events are handed back to the caller to put on the channel.

// defaultUploadWatchlist is the credible, low-false-positive default: chat /
// messaging DESKTOP clients, which have clean open→send semantics. Browsers are
// deliberately excluded (they read cache/profile files and open connections
// constantly); add them via policy uploadProcessWatchlist if desired.
var defaultUploadWatchlist = []string{
	"zalo.exe", "messenger.exe", "telegram.exe", "skype.exe",
	"discord.exe", "viber.exe", "whatsapp.exe", "slack.exe",
	"lark.exe", "wechat.exe", "line.exe",
}

// uploadInterestingExts are document/data/archive/media types worth flagging as
// egress — not the app-noise files (.log, .tmp, .dat, cache blobs, …).
var uploadInterestingExts = map[string]bool{
	".xlsx": true, ".xls": true, ".csv": true, ".doc": true, ".docx": true,
	".pdf": true, ".ppt": true, ".pptx": true, ".txt": true, ".rtf": true,
	".zip": true, ".rar": true, ".7z": true, ".tar": true, ".gz": true,
	".sql": true, ".db": true, ".mdb": true, ".accdb": true,
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
	".mp4": true, ".mov": true, ".avi": true, ".mkv": true,
	".key": true, ".pem": true, ".pfx": true, ".p12": true,
}

// excludedPathParts are lowercased substrings that mark app-internal / system
// locations. A source path containing any of these is NOT user-egress-worthy,
// even with an interesting extension — this is the single biggest FP filter
// (browser/app cache + profile churn).
var excludedPathParts = []string{
	`\appdata\`, `\local settings\`, `\windows\`, `\program files`,
	`\programdata\`, `$recycle.bin`, `\$recycle`, `\temp\`, `\tmp\`,
	`\cache`, `\code cache`, `\service worker`, `\cookies`, `\gpucache`,
	`\crashpad`, `\indexeddb`, `\microsoft\`, `\packages\`,
}

// userDocMarkers are lowercased substrings that mark a genuine user document
// location. A local path must contain one (UNC shares are allowed separately).
var userDocMarkers = []string{
	`\documents\`, `\desktop\`, `\downloads\`, `\pictures\`,
	`\my documents\`, `\onedrive\`, `\dropbox\`, `\google drive\`,
}

type openRec struct {
	path string
	size int64
	t    time.Time
}

type dnsRec struct {
	domain string
	t      time.Time
}

type correlator struct {
	mu          sync.Mutex
	watchlist   map[string]bool              // lowercased process basenames
	recentOpens map[uint32][]openRec         // pid -> recent interesting opens
	dnsByPid    map[uint32]map[string]dnsRec // pid -> destIP -> {domain,t}
	window      time.Duration                // open→connect correlation window
	dnsTTL      time.Duration
	minSize     int64
	maxPerPid   int
	dd          *deduper
	now         func() time.Time
}

func newCorrelator(cfg Config) *correlator {
	c := &correlator{
		recentOpens: map[uint32][]openRec{},
		dnsByPid:    map[uint32]map[string]dnsRec{},
		window:      15 * time.Second,
		dnsTTL:      5 * time.Minute,
		minSize:     cfg.MinFileSizeBytes,
		maxPerPid:   32,
		dd:          newDeduper(30*time.Second, 4096),
		now:         time.Now,
	}
	c.setWatchlist(cfg.UploadProcessWatchlist)
	return c
}

func (c *correlator) setWatchlist(list []string) {
	wl := list
	if len(wl) == 0 {
		wl = defaultUploadWatchlist
	}
	m := make(map[string]bool, len(wl))
	for _, name := range wl {
		n := strings.ToLower(strings.TrimSpace(name))
		if n != "" {
			m[n] = true
		}
	}
	c.watchlist = m
}

// isWatched reports whether a process image path/name is on the watchlist
// (case-insensitive basename match).
func (c *correlator) isWatched(procName string) bool {
	if procName == "" {
		return false
	}
	base := strings.ToLower(filepath.Base(strings.ReplaceAll(procName, `\`, `/`)))
	return c.watchlist[base]
}

// noteOpen records an interesting file open by a watchlisted process. size may
// be 0 when unknown (Create doesn't always carry it); the size gate is then
// skipped. Called from the Kernel-File consumer thread.
func (c *correlator) noteOpen(pid uint32, procName, path string, size int64) {
	if !c.isWatched(procName) {
		return
	}
	if !isInterestingUploadPath(path) {
		return
	}
	if size > 0 && c.minSize > 0 && size < c.minSize {
		return
	}
	t := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	recs := append(c.pruneOpensLocked(c.recentOpens[pid], t), openRec{path: path, size: size, t: t})
	if len(recs) > c.maxPerPid {
		recs = recs[len(recs)-c.maxPerPid:]
	}
	c.recentOpens[pid] = recs
}

// noteDNS records that a process resolved a domain to a set of IPs. Called from
// the DNS-Client consumer thread.
func (c *correlator) noteDNS(pid uint32, domain string, ips []string) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" || len(ips) == 0 {
		return
	}
	t := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.dnsByPid[pid]
	if m == nil {
		m = map[string]dnsRec{}
		c.dnsByPid[pid] = m
	}
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			m[ip] = dnsRec{domain: domain, t: t}
		}
	}
}

// onConnect correlates an outbound connection with a recent interesting open by
// the same watchlisted process. Returns an app_upload Event to emit, or nil.
// Called from the Kernel-Network consumer thread.
func (c *correlator) onConnect(pid uint32, procName, destIP string, destPort int) *Event {
	if !c.isWatched(procName) {
		return nil
	}
	if !isExternalIP(destIP) {
		return nil
	}
	t := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()

	recs := c.pruneOpensLocked(c.recentOpens[pid], t)
	c.recentOpens[pid] = recs
	if len(recs) == 0 {
		return nil
	}
	// Pick the most recent open as the correlated file.
	best := recs[len(recs)-1]

	domain := ""
	if m := c.dnsByPid[pid]; m != nil {
		if rec, ok := m[destIP]; ok && t.Sub(rec.t) <= c.dnsTTL {
			domain = rec.domain
		}
	}

	// Dedup on (pid, file, destIP) within the deduper window so a burst of
	// connects for one upload collapses to one event.
	key := fmt.Sprintf("%d|%s|%s", pid, best.path, destIP)
	if !c.dd.allow(key) {
		return nil
	}

	details := map[string]any{
		"fileName":    filepath.Base(strings.ReplaceAll(best.path, `\`, `/`)),
		"filePath":    best.path,
		"processName": filepath.Base(strings.ReplaceAll(procName, `\`, `/`)),
		"processPath": procName,
		"destIp":      destIP,
		"destPort":    destPort,
		"confidence":  c.confidence(best, t, domain != ""),
	}
	if best.size > 0 {
		details["sizeBytes"] = best.size
	}
	if domain != "" {
		details["destDomain"] = domain
	}
	return &Event{
		EventID:    egressUploadID(pid, best.path, destIP, t),
		EgressType: EgressAppUpload,
		OccurredAt: t.UTC(),
		Details:    details,
	}
}

// confidence scores the correlation 0..1: closer open→connect timing, a known
// destination domain, and a larger file all raise it.
func (c *correlator) confidence(rec openRec, connectT time.Time, hasDomain bool) float64 {
	score := 0.4
	gap := connectT.Sub(rec.t)
	if gap < 2*time.Second {
		score += 0.35
	} else if gap < 5*time.Second {
		score += 0.2
	} else {
		score += 0.1
	}
	if hasDomain {
		score += 0.15
	}
	if rec.size >= 1<<20 { // >= 1 MB
		score += 0.1
	}
	if score > 1 {
		score = 1
	}
	return score
}

// pruneOpensLocked drops opens older than the correlation window. Caller holds mu.
func (c *correlator) pruneOpensLocked(recs []openRec, now time.Time) []openRec {
	cutoff := now.Add(-c.window)
	out := recs[:0]
	for _, r := range recs {
		if r.t.After(cutoff) {
			out = append(out, r)
		}
	}
	return out
}

// gc drops stale per-PID state (opens past the window, DNS past its TTL). Called
// periodically to bound memory for PIDs that never connect. Safe to call from
// any thread.
func (c *correlator) gc() {
	t := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for pid, recs := range c.recentOpens {
		pruned := c.pruneOpensLocked(recs, t)
		if len(pruned) == 0 {
			delete(c.recentOpens, pid)
		} else {
			c.recentOpens[pid] = pruned
		}
	}
	dnsCutoff := t.Add(-c.dnsTTL)
	for pid, m := range c.dnsByPid {
		for ip, rec := range m {
			if rec.t.Before(dnsCutoff) {
				delete(m, ip)
			}
		}
		if len(m) == 0 {
			delete(c.dnsByPid, pid)
		}
	}
}

// isInterestingUploadPath applies the hard file-path gates that keep false
// positives credible: an interesting extension, in a user-document location (or
// a UNC share), and NOT inside an app/system cache/profile/temp directory.
func isInterestingUploadPath(path string) bool {
	if path == "" {
		return false
	}
	p := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	ext := filepath.Ext(p)
	if !uploadInterestingExts[ext] {
		return false
	}
	for _, bad := range excludedPathParts {
		if strings.Contains(p, bad) {
			return false
		}
	}
	// UNC share (\\server\share\...) counts as a user location.
	if strings.HasPrefix(p, `\\`) {
		return true
	}
	for _, good := range userDocMarkers {
		if strings.Contains(p, good) {
			return true
		}
	}
	return false
}

// isExternalIP reports whether ip is a routable, non-local destination worth
// flagging (excludes loopback, RFC1918/unique-local, link-local, unspecified,
// multicast).
func isExternalIP(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return false
	}
	return true
}

// isAnyIP reports whether s parses as any valid IP address (used to extract
// resolved addresses from a DNS results string; the connect path applies the
// external-only filter separately).
func isAnyIP(s string) bool {
	return net.ParseIP(strings.TrimSpace(s)) != nil
}

// egressUploadID is a stable idempotency key bucketed to the minute so a retried
// correlation collapses server-side while a later genuine upload gets a new id.
func egressUploadID(pid uint32, path, destIP string, t time.Time) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("upload|%d|%s|%s|%d", pid, path, destIP, t.Unix()/60)))
	return hex.EncodeToString(sum[:16])
}
