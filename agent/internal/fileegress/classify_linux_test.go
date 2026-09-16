//go:build linux

package fileegress

import (
	"strings"
	"testing"
)

func TestParseMountinfo(t *testing.T) {
	// Real-ish mountinfo: an internal ext4 root, a USB vfat under /run/media,
	// a CIFS share, a tmpfs, and a mount point with an escaped space.
	const sample = `22 28 0:21 / /proc rw,nosuid - proc proc rw
26 28 0:5 / /dev rw,nosuid - devtmpfs devtmpfs rw
28 1 259:2 / / rw,relatime - ext4 /dev/nvme0n1p2 rw
101 28 8:17 / /run/media/user/USB\040KEY rw,nosuid,nodev - vfat /dev/sdb1 rw
140 28 0:52 / /mnt/share rw,relatime - cifs //fileserver/dept rw
150 28 0:53 / /home/user/nfs rw,relatime - nfs4 server:/export rw`

	got := parseMountinfo(strings.NewReader(sample))
	if len(got) != 6 {
		t.Fatalf("expected 6 entries, got %d: %+v", len(got), got)
	}

	// The escaped-space mount point must decode.
	var usb *mountEntry
	for i := range got {
		if got[i].source == "/dev/sdb1" {
			usb = &got[i]
		}
	}
	if usb == nil {
		t.Fatal("USB mount not parsed")
	}
	if usb.mountPoint != "/run/media/user/USB KEY" {
		t.Fatalf("octal-escaped mount point not decoded: %q", usb.mountPoint)
	}
	if usb.fsType != "vfat" {
		t.Fatalf("USB fsType = %q, want vfat", usb.fsType)
	}
}

func TestClassifyMount(t *testing.T) {
	// isRemovable stub: only /dev/sdb1 is "removable" per sysfs.
	isRemovable := func(source string) bool { return source == "/dev/sdb1" }

	cases := []struct {
		name   string
		m      mountEntry
		want   string
		wantOK bool
	}{
		{"cifs share", mountEntry{"/mnt/share", "cifs", "//fs/dept"}, EgressNetworkShare, true},
		{"nfs4 share", mountEntry{"/home/u/nfs", "nfs4", "srv:/export"}, EgressNetworkShare, true},
		{"sshfs share", mountEntry{"/mnt/remote", "fuse.sshfs", "u@h:/"}, EgressNetworkShare, true},
		{"usb by sysfs removable", mountEntry{"/data/usb", "vfat", "/dev/sdb1"}, EgressRemovable, true},
		{"usb by media path", mountEntry{"/run/media/user/KEY", "exfat", "/dev/sdc1"}, EgressRemovable, true},
		{"internal disk", mountEntry{"/", "ext4", "/dev/nvme0n1p2"}, "", false},
		{"internal home", mountEntry{"/home", "ext4", "/dev/nvme0n1p3"}, "", false},
		{"tmpfs ignored", mountEntry{"/run", "tmpfs", "tmpfs"}, "", false},
		{"proc ignored", mountEntry{"/proc", "proc", "proc"}, "", false},
		{"overlay ignored", mountEntry{"/var/lib/docker/x", "overlay", "overlay"}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := classifyMount(tc.m, isRemovable)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("classifyMount(%+v) = (%q,%v), want (%q,%v)", tc.m, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestParentBlockDevice(t *testing.T) {
	cases := map[string]string{
		"sda":       "sda",
		"sda1":      "sda",
		"sdb15":     "sdb",
		"vda2":      "vda",
		"nvme0n1":   "nvme0n1",
		"nvme0n1p3": "nvme0n1",
		"mmcblk0":   "mmcblk0",
		"mmcblk0p1": "mmcblk0",
	}
	for in, want := range cases {
		if got := parentBlockDevice(in); got != want {
			t.Errorf("parentBlockDevice(%q) = %q, want %q", in, got, want)
		}
	}
}
