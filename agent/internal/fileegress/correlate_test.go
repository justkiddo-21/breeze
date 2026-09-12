package fileegress

import (
	"testing"
	"time"
)

func TestIsInterestingUploadPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{`C:\Users\quanly\Documents\danh-sach.xlsx`, true},
		{`C:\Users\letan\Desktop\report.pdf`, true},
		{`C:\Users\vip1\Downloads\hop-dong.docx`, true},
		{`\\NAS\ketoan\quy3.xlsx`, true},                              // UNC share
		{`C:\Users\quanly\OneDrive\khach-hang.csv`, true},
		{`C:\Users\quanly\AppData\Local\Zalo\cache\blob_1.xlsx`, false}, // app cache
		{`C:\Users\quanly\AppData\Roaming\app\data.csv`, false},         // appdata
		{`C:\Windows\Temp\x.zip`, false},                               // temp/windows
		{`C:\Users\q\Documents\notes.log`, false},                      // uninteresting ext
		{`C:\Program Files\App\readme.pdf`, false},                     // program files
		{`C:\Users\q\Documents\Cache\c.pdf`, false},                    // cache dir
		{`C:\Users\q\Documents\report`, false},                         // no ext
		{``, false},
	}
	for _, tt := range tests {
		if got := isInterestingUploadPath(tt.path); got != tt.want {
			t.Errorf("isInterestingUploadPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsExternalIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"203.162.71.120", true},   // public (zalo)
		{"157.240.199.35", true},   // public (facebook)
		{"127.0.0.1", false},       // loopback
		{"10.22.0.41", false},      // private
		{"192.168.1.10", false},    // private
		{"172.16.5.5", false},      // private
		{"169.254.1.1", false},     // link-local
		{"::1", false},             // loopback v6
		{"fc00::1", false},         // unique-local v6
		{"", false},
		{"not-an-ip", false},
	}
	for _, tt := range tests {
		if got := isExternalIP(tt.ip); got != tt.want {
			t.Errorf("isExternalIP(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func newTestCorrelator(now *time.Time) *correlator {
	c := newCorrelator(Config{Enabled: true})
	c.now = func() time.Time { return *now }
	c.dd.now = func() time.Time { return *now }
	return c
}

func TestCorrelator_HappyPath(t *testing.T) {
	now := time.Unix(1000, 0)
	c := newTestCorrelator(&now)

	c.noteDNS(42, "zalo.me", []string{"203.162.71.120"})
	c.noteOpen(42, `C:\Program Files\Zalo\Zalo.exe`, `C:\Users\q\Documents\khach-hang.xlsx`, 500000)
	now = now.Add(1 * time.Second)

	ev := c.onConnect(42, `C:\Program Files\Zalo\Zalo.exe`, "203.162.71.120", 443)
	if ev == nil {
		t.Fatal("expected an app_upload event")
	}
	if ev.EgressType != EgressAppUpload {
		t.Fatalf("egressType = %q", ev.EgressType)
	}
	if ev.Details["fileName"] != "khach-hang.xlsx" {
		t.Fatalf("fileName = %v", ev.Details["fileName"])
	}
	if ev.Details["destDomain"] != "zalo.me" {
		t.Fatalf("destDomain = %v (want zalo.me from DNS cache)", ev.Details["destDomain"])
	}
	if ev.Details["processName"] != "Zalo.exe" {
		t.Fatalf("processName = %v", ev.Details["processName"])
	}
	// A second connect for the same (pid,file,ip) dedupes to nil.
	if dup := c.onConnect(42, `C:\Program Files\Zalo\Zalo.exe`, "203.162.71.120", 443); dup != nil {
		t.Fatal("expected duplicate connect to be suppressed")
	}
}

func TestCorrelator_Gates(t *testing.T) {
	now := time.Unix(2000, 0)

	t.Run("non-watchlisted process ignored", func(t *testing.T) {
		c := newTestCorrelator(&now)
		c.noteOpen(1, `notepad.exe`, `C:\Users\q\Documents\a.xlsx`, 1000)
		if ev := c.onConnect(1, `notepad.exe`, "8.8.8.8", 443); ev != nil {
			t.Fatal("non-watchlisted process should not correlate")
		}
	})

	t.Run("internal destination ignored", func(t *testing.T) {
		c := newTestCorrelator(&now)
		c.noteOpen(2, `Zalo.exe`, `C:\Users\q\Documents\a.xlsx`, 1000)
		if ev := c.onConnect(2, `Zalo.exe`, "192.168.1.5", 443); ev != nil {
			t.Fatal("internal destination should not correlate")
		}
	})

	t.Run("no recent open -> nil", func(t *testing.T) {
		c := newTestCorrelator(&now)
		if ev := c.onConnect(3, `Zalo.exe`, "8.8.8.8", 443); ev != nil {
			t.Fatal("connect with no recent open should not correlate")
		}
	})

	t.Run("open outside window -> nil", func(t *testing.T) {
		local := time.Unix(3000, 0)
		c := newTestCorrelator(&local)
		c.noteOpen(4, `Zalo.exe`, `C:\Users\q\Documents\a.xlsx`, 1000)
		local = local.Add(20 * time.Second) // window is 15s
		if ev := c.onConnect(4, `Zalo.exe`, "8.8.8.8", 443); ev != nil {
			t.Fatal("open older than the window should not correlate")
		}
	})

	t.Run("cache-file open ignored (FP gate)", func(t *testing.T) {
		c := newTestCorrelator(&now)
		c.noteOpen(5, `Zalo.exe`, `C:\Users\q\AppData\Local\Zalo\cache\x.jpg`, 1000)
		if ev := c.onConnect(5, `Zalo.exe`, "8.8.8.8", 443); ev != nil {
			t.Fatal("cache-file open should be gated out")
		}
	})

	t.Run("no DNS -> event still emits without destDomain", func(t *testing.T) {
		c := newTestCorrelator(&now)
		c.noteOpen(6, `Zalo.exe`, `C:\Users\q\Documents\a.xlsx`, 1000)
		ev := c.onConnect(6, `Zalo.exe`, "8.8.8.8", 443)
		if ev == nil {
			t.Fatal("expected event even without a DNS-resolved domain")
		}
		if _, ok := ev.Details["destDomain"]; ok {
			t.Fatal("destDomain should be absent when DNS cache has no match")
		}
	})
}

func TestCorrelator_CustomWatchlist(t *testing.T) {
	now := time.Unix(4000, 0)
	c := newCorrelator(Config{Enabled: true, UploadProcessWatchlist: []string{"chrome.exe"}})
	c.now = func() time.Time { return now }
	c.dd.now = func() time.Time { return now }

	// chrome watched now, zalo not (custom list replaces default).
	if !c.isWatched(`C:\Program Files\Google\Chrome\chrome.exe`) {
		t.Fatal("chrome.exe should be watched by custom list")
	}
	if c.isWatched(`Zalo.exe`) {
		t.Fatal("Zalo.exe should NOT be watched when a custom list is set")
	}
}

func TestCorrelator_GCBoundsMemory(t *testing.T) {
	now := time.Unix(5000, 0)
	c := newTestCorrelator(&now)
	c.noteOpen(7, `Zalo.exe`, `C:\Users\q\Documents\a.xlsx`, 1000)
	c.noteDNS(7, "zalo.me", []string{"203.162.71.120"})
	now = now.Add(10 * time.Minute) // past window + dnsTTL
	c.gc()
	if len(c.recentOpens) != 0 {
		t.Fatalf("expected opens GC'd, got %d", len(c.recentOpens))
	}
	if len(c.dnsByPid) != 0 {
		t.Fatalf("expected dns GC'd, got %d", len(c.dnsByPid))
	}
}
