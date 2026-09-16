//go:build linux

package fileegress

import (
	"strings"
	"testing"
)

func TestParseHexAddr(t *testing.T) {
	cases := []struct {
		field    string
		v6       bool
		wantIP   string
		wantPort int
		wantOK   bool
	}{
		{"0100007F:0035", false, "127.0.0.1", 53, true},                  // loopback:53
		{"7847A2CB:01BB", false, "203.162.71.120", 443, true},            // public:443 (little-endian word)
		{"00000000000000000000000001000000:0035", true, "::1", 53, true}, // v6 loopback
		{"bogus", false, "", 0, false},
		{"ZZ:01", false, "", 0, false},
	}
	for _, c := range cases {
		ip, port, ok := parseHexAddr(c.field, c.v6)
		if ok != c.wantOK || ip != c.wantIP || port != c.wantPort {
			t.Errorf("parseHexAddr(%q,%v) = (%q,%d,%v), want (%q,%d,%v)",
				c.field, c.v6, ip, port, ok, c.wantIP, c.wantPort, c.wantOK)
		}
	}
}

func TestParseSocketInode(t *testing.T) {
	cases := map[string]struct {
		want uint64
		ok   bool
	}{
		"socket:[12345]":         {12345, true},
		"socket:[0]":             {0, true},
		"pipe:[999]":             {0, false},
		"/dev/null":              {0, false},
		"anon_inode:[eventpoll]": {0, false},
		"socket:[abc]":           {0, false},
	}
	for link, want := range cases {
		got, ok := parseSocketInode(link)
		if got != want.want || ok != want.ok {
			t.Errorf("parseSocketInode(%q) = (%d,%v), want (%d,%v)", link, got, ok, want.want, want.ok)
		}
	}
}

func TestParseProcNetTCP(t *testing.T) {
	// Header, a LISTEN row (filtered), an ESTABLISHED external row (kept), and an
	// ESTABLISHED loopback row (filtered as non-external).
	const sample = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:C3B2 7847A2CB:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:C3B4 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0000000000000000 20 4 30 10 -1`

	conns := parseProcNetTCP(strings.NewReader(sample), false)
	if len(conns) != 1 {
		t.Fatalf("expected 1 external conn, got %d: %+v", len(conns), conns)
	}
	c := conns[0]
	if c.remoteIP != "203.162.71.120" || c.remotePort != 443 || c.inode != 67890 {
		t.Fatalf("conn = %+v, want {203.162.71.120 443 67890}", c)
	}
}
