//go:build windows

package fileegress

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
)

// Wave 2b Windows wiring: a SEPARATE low-volume ETW session for outbound TCP
// connects (Microsoft-Windows-Kernel-Network) and DNS resolutions
// (Microsoft-Windows-DNS-Client), feeding the connect-driven correlator. Kept
// out of the high-volume Kernel-File session so file-event pressure can't starve
// these (design review Q4).
//
// TODO(windows-spike): the following MUST be confirmed against a real Windows
// box before trusting runtime output — they cannot be validated on the Linux
// build host:
//   - the exact Kernel-Network connect event IDs (kernelNetworkConnectEventIDs)
//   - the property names/encodings: daddr (InAddr), dport (big-endian!), and
//     whether PID comes from the header or a payload property
//   - the DNS-Client query-completed event ID (3008) and QueryName/QueryResults
//     property names + the QueryResults value format
const (
	kernelNetworkProviderGUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}"
	dnsClientProviderGUID     = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"
	dnsQueryCompletedEventID  = 3008
	netSessionName            = "Breeze-FileEgress-Net"
)

// TODO(windows-spike): confirm. Microsoft-Windows-Kernel-Network TCP connect
// (SYN) events — IPv4 and IPv6. These are the outbound-initiation events (fire
// before TLS, so they land right after the source file open).
var kernelNetworkConnectEventIDs = map[uint16]bool{
	12: true, // TCP IPv4 connect (candidate)
	28: true, // TCP IPv6 connect (candidate)
}

// startNetworkSession opens the second real-time session and wires its consumer
// callback. Non-fatal to the caller on error.
func (s *etwSubscriber) startNetworkSession() error {
	session := etw.NewRealTimeSession(netSessionName)

	for _, guid := range []string{kernelNetworkProviderGUID, dnsClientProviderGUID} {
		provider, err := etw.ParseProvider(guid)
		if err != nil {
			_ = session.Stop()
			return err
		}
		if err := session.EnableProvider(provider); err != nil {
			_ = session.Stop()
			return err
		}
	}

	s.netSession = session
	s.netDoneCh = make(chan struct{})
	s.netConsumer = etw.NewRealTimeConsumer(context.Background()).FromSessions(session)
	s.netConsumer.EventRecordHelperCallback = s.onNetEvent

	go func() {
		defer close(s.netDoneCh)
		if err := s.netConsumer.Start(); err != nil {
			log.Error("fileegress: net ETW consumer start failed", "error", err.Error())
			return
		}
		for range s.netConsumer.Events {
		}
	}()
	return nil
}

// onNetEvent routes events from the network+DNS session to the correlator.
func (s *etwSubscriber) onNetEvent(h *etw.EventRecordHelper) error {
	id := h.EventID()

	// DNS query completed: cache resolvedIP -> domain for this PID so a later
	// connect to one of those IPs can be labelled with the real service name.
	if id == dnsQueryCompletedEventID {
		name, err := h.GetPropertyString("QueryName")
		if err != nil || name == "" {
			h.Skip()
			return nil
		}
		results, _ := h.GetPropertyString("QueryResults")
		ips := parseDNSResults(results)
		if len(ips) > 0 {
			s.correlator.noteDNS(h.EventRec.EventHeader.ProcessId, name, ips)
		}
		h.Skip()
		return nil
	}

	if !kernelNetworkConnectEventIDs[id] {
		h.Skip()
		return nil
	}

	// Outbound connect. daddr is the destination IP; dport the destination port.
	destIP, err := h.GetPropertyString("daddr")
	if err != nil || destIP == "" {
		h.Skip()
		return nil
	}
	destPort := parsePort(h)
	pid := h.EventRec.EventHeader.ProcessId
	h.Skip()

	procName := s.nameCache.get(pid)
	if ev := s.correlator.onConnect(pid, procName, destIP, destPort); ev != nil {
		select {
		case s.events <- *ev:
		default:
			log.Warn("fileegress: event channel full, dropping upload event", "dest", destIP)
		}
	}
	return nil
}

// parsePort reads the destination port. TODO(windows-spike): Kernel-Network
// dport is network-byte-order; TDH sometimes returns it already converted and
// sometimes not — confirm and byte-swap if needed.
func parsePort(h *etw.EventRecordHelper) int {
	s, err := h.GetPropertyString("dport")
	if err != nil || s == "" {
		return 0
	}
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return 0
}

// parseDNSResults extracts IP addresses from a DNS-Client QueryResults string.
// TODO(windows-spike): confirm the exact format. Observed shape is a
// semicolon-separated list where entries may be prefixed with "type: N " and
// IPv6 may be bracketed; we defensively pull anything that parses as an IP.
func parseDNSResults(results string) []string {
	if results == "" {
		return nil
	}
	var out []string
	for _, part := range strings.FieldsFunc(results, func(r rune) bool {
		return r == ';' || r == ' ' || r == ',' || r == '\t'
	}) {
		p := strings.Trim(part, "[]")
		if isAnyIP(p) {
			out = append(out, p)
		}
	}
	return out
}

// procNameCache maps a PID to its process image path with a short TTL, so the
// per-Create-event and per-connect name lookups don't hit OpenProcess every
// time (the design review's cost concern).
type procNameCache struct {
	mu  sync.Mutex
	m   map[uint32]procNameRec
	ttl time.Duration
	now func() time.Time
}

type procNameRec struct {
	name string
	t    time.Time
}

func newProcNameCache() *procNameCache {
	return &procNameCache{m: map[uint32]procNameRec{}, ttl: 30 * time.Second, now: time.Now}
}

func (c *procNameCache) get(pid uint32) string {
	t := c.now()
	c.mu.Lock()
	if rec, ok := c.m[pid]; ok && t.Sub(rec.t) < c.ttl {
		c.mu.Unlock()
		return rec.name
	}
	c.mu.Unlock()

	name := processImageName(pid) // syscall on miss (classify_windows.go)

	c.mu.Lock()
	c.m[pid] = procNameRec{name: name, t: t}
	c.mu.Unlock()
	return name
}

func (c *procNameCache) gc() {
	t := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for pid, rec := range c.m {
		if t.Sub(rec.t) >= c.ttl {
			delete(c.m, pid)
		}
	}
}
