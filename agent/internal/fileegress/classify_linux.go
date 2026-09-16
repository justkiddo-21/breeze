//go:build linux

package fileegress

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// mountEntry is the subset of a /proc/self/mountinfo line we classify on.
type mountEntry struct {
	mountPoint string
	fsType     string
	source     string // device or remote (e.g. /dev/sda1, //server/share)
}

// networkFSTypes are the mountinfo fstypes that mean "writing here leaves the
// machine over the network" — a network-share egress surface.
var networkFSTypes = map[string]bool{
	"cifs": true, "smb3": true, "smbfs": true, "smb": true,
	"nfs": true, "nfs4": true, "ncpfs": true,
	"afs": true, "9p": true, "glusterfs": true, "ceph": true, "fuse.sshfs": true,
}

// removableMountPrefixes are where desktop automounters (udisks2/GNOME) put
// USB/removable volumes. Used as a fallback when the sysfs removable flag is
// unavailable (e.g. a bind mount).
var removableMountPrefixes = []string{"/media/", "/run/media/", "/mnt/"}

// parseMountinfo parses /proc/self/mountinfo. Format per line:
//
//	ID pID major:minor root mountPoint options [optional...] - fsType source superOpts
//
// The variable optional-fields section is terminated by a literal " - ".
func parseMountinfo(r io.Reader) []mountEntry {
	var out []mountEntry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		sep := strings.Index(line, " - ")
		if sep < 0 {
			continue
		}
		left := strings.Fields(line[:sep])
		right := strings.Fields(line[sep+3:])
		if len(left) < 5 || len(right) < 2 {
			continue
		}
		out = append(out, mountEntry{
			mountPoint: unescapeOctal(left[4]),
			fsType:     right[0],
			source:     unescapeOctal(right[1]),
		})
	}
	return out
}

// unescapeOctal decodes mountinfo's \NNN octal escapes (space=\040, tab=\011,
// newline=\012, backslash=\134) that appear in mount points with those chars.
var octalEsc = regexp.MustCompile(`\\([0-7]{3})`)

func unescapeOctal(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	return octalEsc.ReplaceAllStringFunc(s, func(m string) string {
		var v int
		for _, c := range m[1:] {
			v = v*8 + int(c-'0')
		}
		return string(rune(v))
	})
}

// classifyMount returns the egress surface for a mount, or ("", false) if it is
// not an egress surface (an ordinary internal disk). isRemovable is injected so
// the sysfs lookup can be stubbed in tests.
func classifyMount(m mountEntry, isRemovable func(source string) bool) (egressType string, ok bool) {
	// A network filesystem is always a network-share surface, wherever mounted.
	if networkFSTypes[strings.ToLower(m.fsType)] {
		return EgressNetworkShare, true
	}
	// Skip pseudo/virtual filesystems outright — they are never egress.
	switch strings.ToLower(m.fsType) {
	case "proc", "sysfs", "devtmpfs", "tmpfs", "cgroup", "cgroup2", "devpts",
		"mqueue", "debugfs", "tracefs", "securityfs", "pstore", "bpf",
		"configfs", "fusectl", "hugetlbfs", "overlay", "squashfs", "autofs",
		"binfmt_misc", "efivarfs", "ramfs":
		return "", false
	}
	// A block device the kernel marks removable is a USB/removable surface.
	if isRemovable != nil && isRemovable(m.source) {
		return EgressRemovable, true
	}
	// Fallback: desktop automounters place removable media under these paths.
	mp := m.mountPoint
	if !strings.HasSuffix(mp, "/") {
		mp += "/"
	}
	for _, p := range removableMountPrefixes {
		if strings.HasPrefix(mp, p) {
			return EgressRemovable, true
		}
	}
	return "", false
}

// blockDeviceRemovable reports whether the block device backing source is marked
// removable in sysfs (/sys/block/<dev>/removable == "1"). A partition source
// (/dev/sda1, /dev/nvme0n1p2) is resolved to its parent device. Non-/dev
// sources (bind mounts, remote) return false.
func blockDeviceRemovable(source string) bool {
	if !strings.HasPrefix(source, "/dev/") {
		return false
	}
	dev := filepath.Base(source)
	parent := parentBlockDevice(dev)
	data, err := os.ReadFile(filepath.Join("/sys/block", parent, "removable"))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}

// parentBlockDevice maps a partition name to its whole-disk device:
// sda1->sda, sdb->sdb, nvme0n1p3->nvme0n1, mmcblk0p1->mmcblk0.
func parentBlockDevice(dev string) string {
	if strings.HasPrefix(dev, "nvme") || strings.HasPrefix(dev, "mmcblk") {
		if i := strings.LastIndex(dev, "p"); i > 0 {
			// only strip a trailing pN partition suffix
			if allDigits(dev[i+1:]) {
				return dev[:i]
			}
		}
		return dev
	}
	// sdaN / vdaN / hdaN: strip trailing digits.
	return strings.TrimRight(dev, "0123456789")
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
