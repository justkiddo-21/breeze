package fileegress

import (
	"testing"
	"time"
)

func TestParseFileEgressConfig(t *testing.T) {
	raw := map[string]any{
		"enabled":                true,
		"watch_removable":        true,
		"watch_network_shares":   false,
		"watch_uploads":          true,
		"upload_process_watchlist": []any{"chrome.exe", "Zalo.exe"},
		"ignore_globs":           []any{"*.tmp"},
		"min_file_size_bytes":    float64(4096),
	}
	cfg, ok := ParseFileEgressConfig(raw)
	if !ok {
		t.Fatal("expected ok")
	}
	if !cfg.Enabled || !cfg.WatchRemovable || cfg.WatchNetworkShares || !cfg.WatchUploads {
		t.Fatalf("flags wrong: %+v", cfg)
	}
	if len(cfg.UploadProcessWatchlist) != 2 || cfg.UploadProcessWatchlist[0] != "chrome.exe" {
		t.Fatalf("watchlist wrong: %+v", cfg.UploadProcessWatchlist)
	}
	if cfg.MinFileSizeBytes != 4096 {
		t.Fatalf("min size wrong: %d", cfg.MinFileSizeBytes)
	}
}

func TestParseFileEgressConfig_NilWatchlistIsNil(t *testing.T) {
	cfg, ok := ParseFileEgressConfig(map[string]any{"enabled": true})
	if !ok {
		t.Fatal("expected ok")
	}
	if cfg.UploadProcessWatchlist != nil {
		t.Fatalf("expected nil watchlist, got %+v", cfg.UploadProcessWatchlist)
	}
}

func TestShouldReport(t *testing.T) {
	base := Config{
		Enabled:            true,
		WatchRemovable:     true,
		WatchNetworkShares: true,
		WatchUploads:       true,
	}
	tests := []struct {
		name       string
		cfg        Config
		egressType string
		path       string
		size       int64
		want       bool
	}{
		{"removable allowed", base, EgressRemovable, `E:\secret.xlsx`, 100, true},
		{"network allowed", base, EgressNetworkShare, `\\srv\share\a.doc`, 100, true},
		{"upload allowed", base, EgressAppUpload, `C:\Users\k\a.pdf`, 100, true},
		{"disabled blocks all", Config{Enabled: false, WatchRemovable: true}, EgressRemovable, `E:\a`, 1, false},
		{"removable off", Config{Enabled: true, WatchRemovable: false}, EgressRemovable, `E:\a`, 1, false},
		{"network off", Config{Enabled: true, WatchNetworkShares: false}, EgressNetworkShare, `\\s\a`, 1, false},
		{"uploads off", Config{Enabled: true, WatchUploads: false}, EgressAppUpload, `C:\a`, 1, false},
		{"unknown type", base, "bogus", `E:\a`, 1, false},
		{
			"below min size",
			Config{Enabled: true, WatchRemovable: true, MinFileSizeBytes: 1000},
			EgressRemovable, `E:\a`, 500, false,
		},
		{
			"at/above min size",
			Config{Enabled: true, WatchRemovable: true, MinFileSizeBytes: 1000},
			EgressRemovable, `E:\a`, 1000, true,
		},
		{
			"unknown size (0) passes min-size gate",
			Config{Enabled: true, WatchRemovable: true, MinFileSizeBytes: 1000},
			EgressRemovable, `E:\a`, 0, true,
		},
		{
			"glob ignores tmp",
			Config{Enabled: true, WatchRemovable: true, IgnoreGlobs: []string{"*.tmp"}},
			EgressRemovable, `E:\build\out.tmp`, 100, false,
		},
		{
			"glob substring path",
			Config{Enabled: true, WatchRemovable: true, IgnoreGlobs: []string{"node_modules"}},
			EgressRemovable, `E:\proj\node_modules\x.js`, 100, false,
		},
		{
			"glob non-match passes",
			Config{Enabled: true, WatchRemovable: true, IgnoreGlobs: []string{"*.tmp"}},
			EgressRemovable, `E:\report.xlsx`, 100, true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.ShouldReport(tt.egressType, tt.path, tt.size); got != tt.want {
				t.Fatalf("ShouldReport(%q,%q,%d) = %v, want %v", tt.egressType, tt.path, tt.size, got, tt.want)
			}
		})
	}
}

func TestDeduper(t *testing.T) {
	now := time.Unix(0, 0)
	d := newDeduper(30*time.Second, 100)
	d.now = func() time.Time { return now }

	if !d.allow("k1") {
		t.Fatal("first sight should pass")
	}
	if d.allow("k1") {
		t.Fatal("immediate repeat should be suppressed")
	}
	if !d.allow("k2") {
		t.Fatal("distinct key should pass")
	}

	// Advance past the window: the key is allowed again.
	now = now.Add(31 * time.Second)
	if !d.allow("k1") {
		t.Fatal("after window, key should pass again")
	}
}

func TestDeduperPruneBoundsMemory(t *testing.T) {
	now := time.Unix(0, 0)
	d := newDeduper(1*time.Second, 1000)
	d.now = func() time.Time { return now }
	for i := 0; i < 500; i++ {
		d.allow(string(rune('a')+rune(i%26)) + time.Duration(i).String())
	}
	now = now.Add(2 * time.Second)
	d.prune()
	if len(d.seen) != 0 {
		t.Fatalf("expected all pruned after window, got %d", len(d.seen))
	}
}
