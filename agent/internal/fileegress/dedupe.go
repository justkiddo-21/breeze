package fileegress

import "time"

// deduper suppresses repeat events with the same key inside a time window, and
// bounds its own memory. Not safe for concurrent use — it is owned by the
// single Start goroutine.
type deduper struct {
	window  time.Duration
	maxKeys int
	seen    map[string]time.Time
	now     func() time.Time // injectable for tests
}

func newDeduper(window time.Duration, maxKeys int) *deduper {
	return &deduper{
		window:  window,
		maxKeys: maxKeys,
		seen:    make(map[string]time.Time),
		now:     time.Now,
	}
}

// allow reports whether an event with this key should pass (true) or be
// suppressed as a duplicate within the window (false). A passing key is
// recorded as just-seen.
func (d *deduper) allow(key string) bool {
	t := d.now()
	if last, ok := d.seen[key]; ok && t.Sub(last) < d.window {
		return false
	}
	// Hard cap: if the table is full of live keys, prune expired ones; if still
	// full, allow the event rather than block detection (fail open for DLP).
	if len(d.seen) >= d.maxKeys {
		d.prune()
		if len(d.seen) >= d.maxKeys {
			return true
		}
	}
	d.seen[key] = t
	return true
}

// prune drops entries older than the window.
func (d *deduper) prune() {
	cutoff := d.now().Add(-d.window)
	for k, t := range d.seen {
		if t.Before(cutoff) {
			delete(d.seen, k)
		}
	}
}
