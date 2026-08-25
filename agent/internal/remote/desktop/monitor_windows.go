//go:build windows

package desktop

import (
	"fmt"
	"log/slog"
	"syscall"
	"unsafe"
)

// DXGI_OUTPUT_DESC layout:
//
//	WCHAR DeviceName[32]  — 64 bytes (UTF-16)
//	RECT  DesktopCoordinates — 16 bytes (left, top, right, bottom int32)
//	BOOL  AttachedToDesktop  — 4 bytes
//	DXGI_MODE_ROTATION — 4 bytes
//	HMONITOR — 8 bytes (pointer)
//
// Total: 96 bytes
type dxgiOutputDesc struct {
	DeviceName        [32]uint16
	Left              int32
	Top               int32
	Right             int32
	Bottom            int32
	AttachedToDesktop int32
	Rotation          uint32
	Monitor           uintptr
}

const (
	dxgiOutputGetDesc = 7 // IDXGIOutput::GetDesc (IUnknown=3, IDXGIObject=4 more, GetDesc=next)
)

// ListMonitors returns every logical display on the desktop.
//
// It starts from the DXGI enumeration (listMonitorsDXGI) and SUPPLEMENTS it with
// any logical display that DXGI missed, discovered via EnumDisplayMonitors (GDI,
// which reports the OS's logical displays regardless of GPU adapter or DXGI
// availability). This ordering is deliberate: the DXGI entries keep their raw
// EnumOutputs index, which the capture path's EnumOutputs(DisplayIndex) relies
// on — reordering them would make monitor switching capture the wrong output on
// machines where DXGI already works. Supplemented monitors get fresh indices
// after the DXGI ones; the capture path can't reach them through DXGI (that's
// why they were missing) and falls back to a GDI region capture keyed by the
// monitor's device name (see gdiCapturer.ensureHandles).
//
// The real-world case this fixes: a single-GPU box with two extended displays
// where one output (e.g. a TV) returns DXGI_ERROR_NOT_CURRENTLY_AVAILABLE
// (0x887A0022) and breaks the DXGI EnumOutputs loop early, so only the first
// monitor is listed even though the second is a live, extended desktop.
func ListMonitors() ([]MonitorInfo, error) {
	dxgi, dxgiErr := listMonitorsDXGI()

	monitors := append([]MonitorInfo(nil), dxgi...)
	// Dedup by geometry, not device name: DXGI's OUTPUT_DESC.DeviceName and GDI's
	// MONITORINFOEX.szDevice are both the `\\.\DISPLAYn` GDI name and normally
	// match, but keying on bounds is robust even if a driver reports them
	// differently — two entries covering the same rectangle are the same display,
	// so 404-style machines (DXGI already sees every monitor) never get phantom
	// duplicates appended.
	boundsKey := func(x, y, w, h int) string {
		return fmt.Sprintf("%d,%d,%d,%d", x, y, w, h)
	}
	seen := make(map[string]bool, len(monitors))
	maxIndex := -1
	for _, m := range monitors {
		seen[boundsKey(m.X, m.Y, m.Width, m.Height)] = true
		if m.Index > maxIndex {
			maxIndex = m.Index
		}
	}

	gdi, gdiErr := enumerateMonitors()
	if gdiErr != nil {
		slog.Warn("EnumDisplayMonitors failed", "error", gdiErr.Error())
	}
	for _, g := range gdi {
		gx, gy := int(g.Left), int(g.Top)
		gw, gh := int(g.Right-g.Left), int(g.Bottom-g.Top)
		if gw <= 0 || gh <= 0 {
			continue
		}
		key := boundsKey(gx, gy, gw, gh)
		if seen[key] {
			continue
		}
		seen[key] = true
		maxIndex++
		monitors = append(monitors, MonitorInfo{
			Index:     maxIndex,
			Name:      g.Device,
			Width:     gw,
			Height:    gh,
			X:         gx,
			Y:         gy,
			IsPrimary: g.Primary,
		})
		slog.Info("ListMonitors: supplemented a display DXGI could not enumerate",
			"index", maxIndex, "device", g.Device,
			"bounds", fmt.Sprintf("%dx%d+%d+%d", gw, gh, gx, gy))
	}

	if len(monitors) == 0 {
		if dxgiErr != nil {
			return nil, dxgiErr
		}
		return nil, fmt.Errorf("no monitors found")
	}
	return monitors, nil
}

// listMonitorsDXGI enumerates connected displays via DXGI (one adapter's
// outputs). It is the base of ListMonitors; see that function for why its
// result is supplemented rather than trusted as complete.
func listMonitorsDXGI() ([]MonitorInfo, error) {
	// Create a temporary D3D11 device to enumerate outputs.
	var device, context uintptr
	featureLevel := uint32(d3dFeatureLevel11_0)
	var actualLevel uint32

	hr, _, _ := procD3D11CreateDevice.Call(
		0,
		uintptr(d3dDriverTypeHardware),
		0,
		0, // No special flags needed for enumeration
		uintptr(unsafe.Pointer(&featureLevel)),
		1,
		uintptr(d3d11SDKVersion),
		uintptr(unsafe.Pointer(&device)),
		uintptr(unsafe.Pointer(&actualLevel)),
		uintptr(unsafe.Pointer(&context)),
	)
	if int32(hr) < 0 {
		return nil, fmt.Errorf("D3D11CreateDevice failed: 0x%08X", uint32(hr))
	}
	defer comRelease(context)
	defer comRelease(device)

	// QueryInterface → IDXGIDevice
	var dxgiDevice uintptr
	_, err := comCall(device, vtblQueryInterface,
		uintptr(unsafe.Pointer(&iidIDXGIDevice)),
		uintptr(unsafe.Pointer(&dxgiDevice)),
	)
	if err != nil {
		return nil, fmt.Errorf("QueryInterface IDXGIDevice: %w", err)
	}
	defer comRelease(dxgiDevice)

	// GetAdapter
	var adapter uintptr
	_, err = comCall(dxgiDevice, dxgiDeviceGetAdapter, uintptr(unsafe.Pointer(&adapter)))
	if err != nil {
		return nil, fmt.Errorf("IDXGIDevice::GetAdapter: %w", err)
	}
	defer comRelease(adapter)

	// Enumerate outputs
	var monitors []MonitorInfo
	for i := 0; ; i++ {
		var output uintptr
		hr, _, _ := syscall.SyscallN(
			comVtblFn(adapter, dxgiAdapterEnumOutputs),
			adapter,
			uintptr(i),
			uintptr(unsafe.Pointer(&output)),
		)
		if int32(hr) < 0 {
			if uint32(hr) != 0x887A0002 { // not DXGI_ERROR_NOT_FOUND
				slog.Warn("DXGI EnumOutputs failed", "index", i, "hr", fmt.Sprintf("0x%08X", uint32(hr)))
			}
			break
		}

		var desc dxgiOutputDesc
		hr, _, _ = syscall.SyscallN(
			comVtblFn(output, dxgiOutputGetDesc),
			output,
			uintptr(unsafe.Pointer(&desc)),
		)
		comRelease(output)

		if int32(hr) < 0 {
			slog.Warn("DXGI GetDesc failed", "index", i, "hr", fmt.Sprintf("0x%08X", uint32(hr)))
			continue
		}

		if desc.AttachedToDesktop == 0 {
			continue
		}

		name := syscall.UTF16ToString(desc.DeviceName[:])
		w := int(desc.Right - desc.Left)
		h := int(desc.Bottom - desc.Top)

		monitors = append(monitors, MonitorInfo{
			Index:     i,
			Name:      name,
			Width:     w,
			Height:    h,
			X:         int(desc.Left),
			Y:         int(desc.Top),
			IsPrimary: desc.Left == 0 && desc.Top == 0,
		})
	}

	if len(monitors) == 0 {
		return nil, fmt.Errorf("no monitors found")
	}

	return monitors, nil
}
