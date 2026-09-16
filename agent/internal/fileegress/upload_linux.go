//go:build linux

package fileegress

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Wave 2b on Linux, without eBPF: a /proc poller feeds the shared correlator.
//
// fanotify has no network side and no cheap per-process file filter, so instead
// of the Windows ETW streams we poll, once a second, only the WATCHLISTED
// processes' own /proc/<pid>/fd table. One scan yields both:
//   - open regular files under user-doc dirs  -> correlator.noteOpen
//   - open socket inodes, matched against /proc/net/tcp{,6} EXTERNAL,
//     ESTABLISHED/SYN_SENT connections        -> correlator.onConnect
//
// This bounds cost to watched apps (chat clients hold their file + connection
// open across an upload, so a 1s poll inside the 15s window catches them) and
// avoids the system-wide fanotify FAN_OPEN firehose. DNS→domain labelling is
// not done here (no cheap Linux source); events still emit with the dest IP.
//
// Trade-off vs eBPF (a later hardening): a transient open→read→close or a very
// short connection that both fall between two polls is missed. Acceptable for a
// v1 heuristic; documented for the runtime spike.

const (
	uploadPollInterval = 1 * time.Second
	connSeenTTL        = 60 * time.Second
	// /proc/net/tcp st values we treat as an outbound connection.
	tcpEstablished = 0x01
	tcpSynSent     = 0x02
)

func (s *fanotifySubscriber) uploadPollLoop() {
	defer s.wg.Done()
	t := time.NewTicker(uploadPollInterval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			s.uploadPollOnce()
		}
	}
}

func (s *fanotifySubscriber) uploadPollOnce() {
	cfg := s.poster.FileEgressConfig()
	if !cfg.Enabled || !cfg.WatchUploads {
		return
	}
	s.corr.setWatchlist(cfg.UploadProcessWatchlist)

	watched := scanWatchedProcs(s.corr.isWatched)
	if len(watched) == 0 {
		s.corr.gc()
		s.pruneConnSeen()
		return
	}

	// inode -> external outbound connection, from both IPv4 and IPv6 tables.
	table := readTCPTable()

	for pid, exe := range watched {
		inodes, files := scanPidFds(pid)
		for _, f := range files {
			s.corr.noteOpen(pid, exe, f.path, f.size)
		}
		for _, ino := range inodes {
			conn, ok := table[ino]
			if !ok {
				continue
			}
			if !s.firstSeenConn(pid, conn.remoteIP, conn.remotePort) {
				continue
			}
			if ev := s.corr.onConnect(pid, exe, conn.remoteIP, conn.remotePort); ev != nil {
				select {
				case s.events <- *ev:
				case <-s.ctx.Done():
					return
				default:
					log.Debug("fileegress: upload event channel full, dropping")
				}
			}
		}
	}
	s.corr.gc()
	s.pruneConnSeen()
}

// firstSeenConn reports whether (pid,ip,port) has not been correlated recently,
// recording it so a long-lived connection is not re-fired every poll.
func (s *fanotifySubscriber) firstSeenConn(pid uint32, ip string, port int) bool {
	key := strconv.FormatUint(uint64(pid), 10) + "|" + ip + "|" + strconv.Itoa(port)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.connSeen[key]; ok && now.Sub(last) < connSeenTTL {
		return false
	}
	s.connSeen[key] = now
	return true
}

func (s *fanotifySubscriber) pruneConnSeen() {
	cutoff := time.Now().Add(-connSeenTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, t := range s.connSeen {
		if t.Before(cutoff) {
			delete(s.connSeen, k)
		}
	}
}

// openFile is a regular file a process has open.
type openFile struct {
	path string
	size int64
}

// scanWatchedProcs returns pid -> exe path for processes whose executable base
// name is on the watchlist. Unreadable /proc/<pid>/exe (kernel threads, denied)
// are skipped.
func scanWatchedProcs(isWatched func(string) bool) map[uint32]string {
	out := map[uint32]string{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue // not a pid dir
		}
		exe, err := os.Readlink("/proc/" + e.Name() + "/exe")
		if err != nil || exe == "" {
			continue
		}
		exe = strings.TrimSuffix(exe, " (deleted)")
		if isWatched(exe) {
			out[uint32(pid64)] = exe
		}
	}
	return out
}

// scanPidFds returns the socket inodes and open regular files of a process from
// its /proc/<pid>/fd table.
func scanPidFds(pid uint32) (socketInodes []uint64, files []openFile) {
	dir := "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/fd"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	for _, e := range entries {
		link, err := os.Readlink(dir + "/" + e.Name())
		if err != nil {
			continue
		}
		if ino, ok := parseSocketInode(link); ok {
			socketInodes = append(socketInodes, ino)
			continue
		}
		// Only real filesystem paths; skip pipe:/anon_inode:/socket: and the
		// obvious non-document trees (cheap pre-filter; noteOpen re-checks).
		if !strings.HasPrefix(link, "/") {
			continue
		}
		info, err := os.Stat(link)
		if err != nil || info.IsDir() {
			continue
		}
		files = append(files, openFile{path: link, size: info.Size()})
	}
	return socketInodes, files
}

// parseSocketInode extracts N from a "socket:[N]" fd link.
func parseSocketInode(link string) (uint64, bool) {
	const p = "socket:["
	if !strings.HasPrefix(link, p) || !strings.HasSuffix(link, "]") {
		return 0, false
	}
	n, err := strconv.ParseUint(link[len(p):len(link)-1], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// tcpConn is one external outbound row from /proc/net/tcp{,6}.
type tcpConn struct {
	remoteIP   string
	remotePort int
	inode      uint64
}

// readTCPTable parses both IPv4 and IPv6 tables into inode -> external conn.
func readTCPTable() map[uint64]tcpConn {
	out := map[uint64]tcpConn{}
	for _, spec := range []struct {
		path string
		v6   bool
	}{{"/proc/net/tcp", false}, {"/proc/net/tcp6", true}} {
		f, err := os.Open(spec.path)
		if err != nil {
			continue
		}
		for _, c := range parseProcNetTCP(f, spec.v6) {
			out[c.inode] = c
		}
		f.Close()
	}
	return out
}

// parseProcNetTCP parses a /proc/net/tcp or tcp6 stream, returning only
// external (routable, non-private) outbound (ESTABLISHED/SYN_SENT) connections.
// Pure over the reader so it is unit-tested with sample tables.
func parseProcNetTCP(r io.Reader, isV6 bool) []tcpConn {
	var out []tcpConn
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first { // header row
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		state, err := strconv.ParseInt(fields[3], 16, 32)
		if err != nil || (state != tcpEstablished && state != tcpSynSent) {
			continue
		}
		ip, port, ok := parseHexAddr(fields[2], isV6) // rem_address
		if !ok || !isExternalIP(ip) {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || inode == 0 {
			continue
		}
		out = append(out, tcpConn{remoteIP: ip, remotePort: port, inode: inode})
	}
	return out
}

// parseHexAddr decodes a /proc/net "HEXIP:HEXPORT" field. The kernel prints the
// address as the in-memory bytes (little-endian per 32-bit word on x86); the
// port is big-endian. IPv4 is 8 hex chars, IPv6 is 32.
func parseHexAddr(field string, isV6 bool) (ip string, port int, ok bool) {
	i := strings.IndexByte(field, ':')
	if i < 0 {
		return "", 0, false
	}
	hexIP, hexPort := field[:i], field[i+1:]
	p, err := strconv.ParseUint(hexPort, 16, 32)
	if err != nil {
		return "", 0, false
	}
	raw, err := hex.DecodeString(hexIP)
	if err != nil {
		return "", 0, false
	}
	if isV6 {
		if len(raw) != 16 {
			return "", 0, false
		}
		b := make([]byte, 16)
		// Reverse each of the four 32-bit words.
		for w := 0; w < 4; w++ {
			word := raw[w*4 : w*4+4]
			for k := 0; k < 4; k++ {
				b[w*4+k] = word[3-k]
			}
		}
		return net.IP(b).String(), int(p), true
	}
	if len(raw) != 4 {
		return "", 0, false
	}
	v := binary.LittleEndian.Uint32(raw)
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return net.IPv4(b[0], b[1], b[2], b[3]).String(), int(p), true
}
