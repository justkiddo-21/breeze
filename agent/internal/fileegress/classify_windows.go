//go:build windows

package fileegress

import (
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows GetDriveType return codes (winbase.h).
const (
	driveRemovable = 2
	driveRemote    = 4
)

var (
	kernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procGetDriveTypeW = kernel32.NewProc("GetDriveTypeW")
	procQueryDosDevW  = kernel32.NewProc("QueryDosDeviceW")
)

// driveClassifier maps a Kernel-File native path (e.g.
// `\Device\HarddiskVolume5\dir\file.xlsx`) to an egress surface. Removable
// volumes are discovered by walking A:–Z:, keeping those whose GetDriveTypeW is
// DRIVE_REMOVABLE, and resolving each to its NT device prefix via
// QueryDosDeviceW. Network access is matched by well-known redirector prefixes,
// which also covers UNC paths that never got a drive letter.
//
// The removable map is refreshed on a TTL because USB volumes come and go.
type driveClassifier struct {
	mu           sync.Mutex
	refreshedAt  time.Time
	ttl          time.Duration
	removable    map[string]string // NT device prefix (lower) -> drive letter "E:"
	now          func() time.Time
}

func newDriveClassifier() *driveClassifier {
	return &driveClassifier{
		ttl:       10 * time.Second,
		removable: map[string]string{},
		now:       time.Now,
	}
}

// networkPrefixes are the NT device namespaces the SMB/redirector stack uses.
// A Kernel-File path under one of these is a write to a network share,
// regardless of whether the user mapped a drive letter.
var networkPrefixes = []string{
	`\device\mup\`,
	`\device\lanmanredirector\`,
	`\device\webdavredirector\`,
}

// classify returns the egress type for an NT path, or "" if the path is on a
// fixed local disk (not an egress surface). destVolume is the drive letter or
// redirector root for the event details.
func (dc *driveClassifier) classify(ntPath string) (egressType, destVolume string) {
	p := strings.ToLower(ntPath)

	for _, np := range networkPrefixes {
		if strings.HasPrefix(p, np) {
			return EgressNetworkShare, strings.TrimSuffix(np, `\`)
		}
	}

	dc.mu.Lock()
	if dc.now().Sub(dc.refreshedAt) > dc.ttl {
		dc.refreshLocked()
	}
	// Copy the small map reference under lock, then match outside.
	for prefix, letter := range dc.removable {
		if strings.HasPrefix(p, prefix) {
			dc.mu.Unlock()
			return EgressRemovable, letter
		}
	}
	dc.mu.Unlock()
	return "", ""
}

// refreshLocked rebuilds the removable-volume prefix map. Caller holds dc.mu.
func (dc *driveClassifier) refreshLocked() {
	dc.refreshedAt = dc.now()
	next := map[string]string{}
	for c := 'A'; c <= 'Z'; c++ {
		root := string(c) + `:\`
		if driveType(root) != driveRemovable {
			continue
		}
		// QueryDosDeviceW wants the drive without a trailing backslash ("E:").
		dev := queryDosDevice(string(c) + ":")
		if dev == "" {
			continue
		}
		next[strings.ToLower(dev)+`\`] = string(c) + ":"
	}
	dc.removable = next
}

func driveType(root string) uint32 {
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return 0
	}
	r, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(p)))
	return uint32(r)
}

// queryDosDevice resolves "E:" -> `\Device\HarddiskVolumeN` (the first target).
func queryDosDevice(dosName string) string {
	name, err := windows.UTF16PtrFromString(dosName)
	if err != nil {
		return ""
	}
	buf := make([]uint16, 1024)
	r, _, _ := procQueryDosDevW.Call(
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r == 0 {
		return ""
	}
	// The result is a NUL-separated, double-NUL-terminated list; take the first.
	s := windows.UTF16ToString(buf)
	return s
}

// processImageName resolves a PID to its executable path (best effort). The PID
// may have exited by the time the ETW callback runs (TOCTOU) — an empty string
// is fine, the event still carries the surface + path.
func processImageName(pid uint32) string {
	if pid == 0 {
		return ""
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}
