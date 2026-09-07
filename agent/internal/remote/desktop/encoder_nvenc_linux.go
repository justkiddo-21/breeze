//go:build linux

package desktop

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// NV_ENC_PRESET_LOW_LATENCY_HQ_GUID — a legacy preset the non-Ex
// NvEncGetEncodePresetConfig understands (the P1–P7 presets are Ex-only, which
// is why the non-Ex query rejected P4 with INVALID_DEVICE).
var nvencPresetLowLatencyHQGUID = nvencGUID{
	Data1: 0x21c6e6b4, Data2: 0x297a, Data3: 0x4cba,
	Data4: [8]byte{0x99, 0x8f, 0xb6, 0xcb, 0xde, 0x72, 0xad, 0xe3},
}

// guidWords returns a 16-byte NVENC GUID as the two 64-bit eightbytes the
// System V AMD64 ABI passes a by-value struct in (NVENC GUIDs are by value; on
// Linux that means two integer registers, not a pointer).
func guidWords(g nvencGUID) (uint64, uint64) {
	var b [16]byte
	binary.LittleEndian.PutUint32(b[0:], g.Data1)
	binary.LittleEndian.PutUint16(b[4:], g.Data2)
	binary.LittleEndian.PutUint16(b[6:], g.Data3)
	copy(b[8:], g.Data4[:])
	return binary.LittleEndian.Uint64(b[0:8]), binary.LittleEndian.Uint64(b[8:16])
}

// =============================================================================
// NVENC Encoder (Linux) — NVIDIA hardware H264 via NVENC + the CUDA driver API,
// loaded at runtime with purego (no cgo, matching CGO_ENABLED=0 builds).
//
// The Windows sibling (encoder_nvenc_windows.go) feeds NVENC D3D11 GPU textures
// zero-copy. Linux capture produces CPU frames (X11 BGRX), so here we:
//   1. open the NVENC session on a CUDA context (not DirectX),
//   2. keep one CUDA device buffer sized for NV12,
//   3. per frame: BGRX→NV12 on CPU, cuMemcpyHtoD into that buffer, then register
//      it as an NV_ENC_INPUT_RESOURCE_TYPE_CUDADEVICEPTR and Map/Encode/Unmap.
//
// The NVENC structs, GUIDs, config offsets and status strings are shared with
// the Windows build (nvenc_types.go); only the library loading, the session
// device type, and the input path differ.
// =============================================================================

// Device/resource types not needed by the DirectX (Windows) path.
const (
	nvencDeviceTypeCUDA uint32 = 1 // NV_ENC_DEVICE_TYPE_CUDA
	nvencInputResCUDA   uint32 = 2 // NV_ENC_INPUT_RESOURCE_TYPE_CUDADEVICEPTR
)

const cudaSuccess = 0

var (
	nvencLinuxLoadOnce sync.Once
	nvencLinuxLoadErr  error

	nvEncCreateInstancePtr uintptr

	// CUDA driver API entry points (libcuda.so.1).
	cuInitPtr          uintptr
	cuDeviceGetPtr     uintptr
	cuCtxCreatePtr     uintptr
	cuCtxDestroyPtr    uintptr
	cuCtxSetCurrentPtr uintptr
	cuMemAllocPtr      uintptr
	cuMemFreePtr       uintptr
	cuMemcpyHtoDPtr    uintptr
)

func loadNVENCLibsLinux() error {
	nvencLinuxLoadOnce.Do(func() {
		cuda, err := purego.Dlopen("libcuda.so.1", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil || cuda == 0 {
			nvencLinuxLoadErr = fmt.Errorf("dlopen libcuda.so.1: %v (install the NVIDIA driver)", err)
			return
		}
		nvenc, err := purego.Dlopen("libnvidia-encode.so.1", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil || nvenc == 0 {
			nvencLinuxLoadErr = fmt.Errorf("dlopen libnvidia-encode.so.1: %v (install the NVIDIA driver's encode library)", err)
			return
		}
		sym := func(lib uintptr, name string) uintptr {
			p, e := purego.Dlsym(lib, name)
			if e != nil || p == 0 {
				if nvencLinuxLoadErr == nil {
					nvencLinuxLoadErr = fmt.Errorf("dlsym %s: %v", name, e)
				}
			}
			return p
		}
		cuInitPtr = sym(cuda, "cuInit")
		cuDeviceGetPtr = sym(cuda, "cuDeviceGet")
		cuCtxCreatePtr = sym(cuda, "cuCtxCreate_v2")
		cuCtxDestroyPtr = sym(cuda, "cuCtxDestroy_v2")
		cuCtxSetCurrentPtr = sym(cuda, "cuCtxSetCurrent")
		cuMemAllocPtr = sym(cuda, "cuMemAlloc_v2")
		cuMemFreePtr = sym(cuda, "cuMemFree_v2")
		cuMemcpyHtoDPtr = sym(cuda, "cuMemcpyHtoD_v2")
		nvEncCreateInstancePtr = sym(nvenc, "NvEncodeAPICreateInstance")
		if nvencLinuxLoadErr != nil {
			return
		}
		// cuInit(0) must run once before any other CUDA driver call.
		if r, _, _ := purego.SyscallN(cuInitPtr, 0); r != cudaSuccess {
			nvencLinuxLoadErr = fmt.Errorf("cuInit failed: CUDA error %d", r)
			return
		}
		slog.Info("NVENC (Linux) libraries loaded (libnvidia-encode.so.1 + libcuda.so.1)")
	})
	return nvencLinuxLoadErr
}

func init() {
	registerHardwareFactoryForVendor("nvidia", newNVENCEncoderLinux)
}

func newNVENCEncoderLinux(cfg EncoderConfig) (encoderBackend, error) {
	if cfg.Codec != CodecH264 {
		return nil, fmt.Errorf("nvenc: only H264 supported, got %s", cfg.Codec)
	}
	if err := loadNVENCLibsLinux(); err != nil {
		return nil, err
	}
	return &nvencEncoderLinux{cfg: cfg}, nil
}

// nvencEncoderLinux implements encoderBackend using NVENC with a CUDA context.
type nvencEncoderLinux struct {
	mu          sync.Mutex
	cfg         EncoderConfig
	width       int
	height      int
	pixelFormat PixelFormat
	forceIDR    bool
	frameIdx    uint64

	funcs   nvencFuncList
	encoder uintptr // NVENC session handle
	config  nvencConfig

	cuCtx        uintptr // CUDA context
	cuInputDPtr  uint64  // CUDA device buffer holding NV12
	cuBufSize    uint64
	registeredRes uintptr // registered CUDA resource
	bitstreamBuf uintptr

	inited bool
}

// --- encoderBackend interface ---

func (e *nvencEncoderLinux) Name() string {
	if e.inited {
		return "nvenc-hardware-linux"
	}
	return "nvenc-linux"
}

func (e *nvencEncoderLinux) IsHardware() bool    { return true }
func (e *nvencEncoderLinux) IsPlaceholder() bool { return false }

func (e *nvencEncoderLinux) SetCodec(c Codec) error {
	if c != CodecH264 {
		return fmt.Errorf("%w: nvenc only supports H264, got %s", ErrInvalidCodec, c)
	}
	return nil
}

func (e *nvencEncoderLinux) SetQuality(_ QualityPreset) error { return nil }
func (e *nvencEncoderLinux) SetPixelFormat(pf PixelFormat)    { e.pixelFormat = pf }

func (e *nvencEncoderLinux) SetBitrate(bitrate int) error {
	if bitrate <= 0 {
		return ErrInvalidBitrate
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.Bitrate = bitrate
	// Dynamic reconfigure not implemented; bitrate is applied at next init.
	return nil
}

func (e *nvencEncoderLinux) SetFPS(fps int) error {
	if fps <= 0 {
		return ErrInvalidFPS
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.FPS = fps
	return nil
}

func (e *nvencEncoderLinux) SetDimensions(w, h int) error {
	w = w &^ 1 // H264 requires even dimensions
	h = h &^ 1
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.inited && (e.width != w || e.height != h) {
		e.shutdown()
	}
	e.width = w
	e.height = h
	return nil
}

// GPU zero-copy is Windows/D3D11-only; the Linux path takes CPU frames.
func (e *nvencEncoderLinux) SetD3D11Device(_, _ uintptr) {}
func (e *nvencEncoderLinux) SupportsGPUInput() bool      { return false }
func (e *nvencEncoderLinux) IsGPUOnly() bool             { return false }
func (e *nvencEncoderLinux) EncodeTexture(_ uintptr) ([]byte, error) {
	return nil, fmt.Errorf("nvenc-linux: EncodeTexture not supported, use Encode")
}

func (e *nvencEncoderLinux) ForceKeyframe() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.forceIDR = true
	return nil
}

func (e *nvencEncoderLinux) Flush() error { return e.ForceKeyframe() }

func (e *nvencEncoderLinux) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.shutdown()
	return nil
}

// Encode takes a CPU BGRX/BGRA frame, converts to NV12, uploads to the CUDA
// buffer, and encodes it to H264 Annex-B NALUs.
func (e *nvencEncoderLinux) Encode(frame []byte) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// A CUDA context is bound to an OS thread. Pin the goroutine so the context
	// stays current across init, the HtoD copy, and the encode on one thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if !e.inited {
		if err := e.initialize(); err != nil {
			return nil, fmt.Errorf("nvenc-linux init: %w", err)
		}
	}

	// Bind the CUDA context to this thread (idempotent; harmless after init).
	if r, _, _ := purego.SyscallN(cuCtxSetCurrentPtr, e.cuCtx); r != cudaSuccess {
		return nil, fmt.Errorf("cuCtxSetCurrent failed: CUDA error %d", r)
	}

	// BGRX/BGRA → NV12 (stride == width*4 for a tightly packed capture frame).
	stride := e.width * 4
	if len(frame) < stride*e.height {
		return nil, fmt.Errorf("nvenc-linux: short frame %d, want >= %d", len(frame), stride*e.height)
	}
	var nv12 []byte
	if e.pixelFormat == PixelFormatRGBA {
		nv12 = rgbaToNV12(frame, e.width, e.height, stride)
	} else {
		nv12 = bgraToNV12(frame, e.width, e.height, stride)
	}
	defer putNV12Buffer(nv12)
	if uint64(len(nv12)) > e.cuBufSize {
		return nil, fmt.Errorf("nvenc-linux: NV12 %d exceeds CUDA buffer %d", len(nv12), e.cuBufSize)
	}

	// Upload NV12 to the device buffer.
	if r, _, _ := purego.SyscallN(cuMemcpyHtoDPtr,
		uintptr(e.cuInputDPtr),
		uintptr(unsafe.Pointer(&nv12[0])),
		uintptr(len(nv12)),
	); r != cudaSuccess {
		runtime.KeepAlive(nv12)
		return nil, fmt.Errorf("cuMemcpyHtoD failed: CUDA error %d", r)
	}
	runtime.KeepAlive(nv12)

	return e.encodeFrame()
}

// =============================================================================
// Initialization
// =============================================================================

func (e *nvencEncoderLinux) initialize() error {
	if e.width == 0 || e.height == 0 {
		return fmt.Errorf("dimensions not set — call SetDimensions first")
	}

	// Step 0: create a CUDA context on device 0.
	var dev int32
	if r, _, _ := purego.SyscallN(cuDeviceGetPtr, uintptr(unsafe.Pointer(&dev)), 0); r != cudaSuccess {
		return fmt.Errorf("cuDeviceGet failed: CUDA error %d", r)
	}
	if r, _, _ := purego.SyscallN(cuCtxCreatePtr,
		uintptr(unsafe.Pointer(&e.cuCtx)), 0, uintptr(dev),
	); r != cudaSuccess {
		return fmt.Errorf("cuCtxCreate failed: CUDA error %d", r)
	}

	// Step 1: NVENC function table.
	e.funcs = nvencFuncList{}
	e.funcs.Version = nvencStructVer(2)
	if r, _, _ := purego.SyscallN(nvEncCreateInstancePtr, uintptr(unsafe.Pointer(&e.funcs))); r != nvencSuccess {
		e.destroyCUDA()
		return fmt.Errorf("NvEncodeAPICreateInstance failed: %s (0x%X)", nvencStatusStr(r), r)
	}

	// Step 2: open the encode session on the CUDA context.
	var sessionParams nvencOpenSessionParams
	sessionParams.Version = nvencStructVer(1)
	sessionParams.DeviceType = nvencDeviceTypeCUDA
	sessionParams.Device = e.cuCtx
	sessionParams.APIVersion = nvencAPIVersion
	if r, _, _ := purego.SyscallN(e.funcs.OpenEncodeSessionEx,
		uintptr(unsafe.Pointer(&sessionParams)), uintptr(unsafe.Pointer(&e.encoder)),
	); r != nvencSuccess {
		e.destroyCUDA()
		return fmt.Errorf("NvEncOpenEncodeSessionEx failed: %s (0x%X)", nvencStatusStr(r), r)
	}
	slog.Info("nvenc-linux: encode session opened", "encoder", fmt.Sprintf("0x%X", e.encoder))

	// NVENC requires our CUDA context to be CURRENT on the calling thread for
	// device-touching API calls. OpenEncodeSessionEx can leave a different (or
	// no) context current, which makes the very next call return INVALID_DEVICE.
	// Re-assert it before the preset query and the rest of init.
	if r, _, _ := purego.SyscallN(cuCtxSetCurrentPtr, e.cuCtx); r != cudaSuccess {
		e.shutdownSession()
		return fmt.Errorf("cuCtxSetCurrent (post-session) failed: CUDA error %d", r)
	}

	fps := e.cfg.FPS
	if fps <= 0 {
		fps = 30
	}
	bitrate := e.cfg.Bitrate
	if bitrate <= 0 {
		bitrate = 2_500_000
	}
	idrPeriod := uint32(fps * 10)
	if idrPeriod < 30 {
		idrPeriod = 30
	}

	// Step 3: get a valid base NV_ENC_CONFIG from the legacy LOW_LATENCY_HQ
	// preset via the non-Ex query (6 integer args — purego-safe, no stack spill).
	// A NULL config segfaults the driver and a mostly-zero hand-built config is
	// rejected with INVALID_PARAM, so we need real preset defaults to build on.
	// Fall back to a zeroed+versioned config if the query somehow fails.
	e.config = nvencConfig{}
	var presetCfg nvencPresetConfig
	*(*uint32)(unsafe.Pointer(&presetCfg[0])) = nvencStructVerExt(5)
	*(*uint32)(unsafe.Pointer(&presetCfg[8])) = nvencStructVerExt(9)
	*(*uint32)(unsafe.Pointer(&presetCfg[8+ncfgRCVersion])) = nvencStructVer(1)
	codecLo, codecHi := guidWords(nvencCodecH264GUID)
	presetLo, presetHi := guidWords(nvencPresetLowLatencyHQGUID)
	rp, _, _ := purego.SyscallN(e.funcs.GetEncodePresetConfig,
		e.encoder,
		uintptr(codecLo), uintptr(codecHi),
		uintptr(presetLo), uintptr(presetHi),
		uintptr(unsafe.Pointer(&presetCfg)),
	)
	runtime.KeepAlive(presetCfg)
	gotPreset := rp == nvencSuccess
	if gotPreset {
		copy(e.config[:], presetCfg[8:8+3584])
	} else {
		slog.Warn("nvenc-linux: preset query failed, using hand-built config",
			"status", nvencStatusStr(rp), "code", rp)
		ncfgPutU32(&e.config, ncfgVersion, nvencStructVerExt(9)) // NV_ENC_CONFIG_VER
	}

	// Customize the base config (applies to preset-derived or hand-built).
	ncfgPutGUID(&e.config, ncfgProfileGUID, nvencProfileAutoGUID)
	ncfgPutU32(&e.config, ncfgGOPLength, idrPeriod)
	ncfgPutU32(&e.config, ncfgFrameIntervalP, 1) // IP only, no B-frames
	ncfgPutU32(&e.config, ncfgRCVersion, nvencStructVer(1))
	ncfgPutU32(&e.config, ncfgRCMode, nvencRCCBR)
	ncfgPutU32(&e.config, ncfgRCAvgBR, uint32(bitrate))
	ncfgPutU32(&e.config, ncfgRCMaxBR, uint32(bitrate))
	ncfgPutU32(&e.config, ncfgRCVBVBuf, uint32(bitrate/fps))
	ncfgPutU32(&e.config, ncfgRCVBVInit, uint32(bitrate/fps))
	ncfgPutU32(&e.config, ncfgH264IDRPeriod, idrPeriod)
	bits := ncfgGetU32(&e.config, ncfgH264Bitfields)
	bits |= ncfgH264RepeatSPSPPS
	ncfgPutU32(&e.config, ncfgH264Bitfields, bits)

	// Step 4: initialize with the legacy preset GUID + undefined tuning to match
	// the config source (P4 + a tuning expects an Ex-derived config).
	var initParams nvencInitParams
	initParams.Version = nvencStructVerExt(7)
	initParams.EncodeGUID = nvencCodecH264GUID
	initParams.PresetGUID = nvencPresetLowLatencyHQGUID
	initParams.EncodeWidth = uint32(e.width)
	initParams.EncodeHeight = uint32(e.height)
	initParams.DarWidth = uint32(e.width)
	initParams.DarHeight = uint32(e.height)
	initParams.FrameRateNum = uint32(fps)
	initParams.FrameRateDen = 1
	initParams.EnablePTD = 1
	initParams.EncodeConfig = uintptr(unsafe.Pointer(&e.config))
	initParams.TuningInfo = nvencTuningUndef
	rp, _, _ = purego.SyscallN(e.funcs.InitializeEncoder, e.encoder, uintptr(unsafe.Pointer(&initParams)))
	runtime.KeepAlive(e.config)
	runtime.KeepAlive(initParams)
	if rp != nvencSuccess {
		enc := e.encoder
		e.shutdownSession()
		return fmt.Errorf("NvEncInitializeEncoder failed: %s (0x%X) [encoder=0x%X gotPreset=%v]", nvencStatusStr(rp), rp, enc, gotPreset)
	}

	// Step 6: output bitstream buffer.
	var createBuf nvencCreateBitstreamBuffer
	createBuf.Version = nvencStructVer(1)
	if r, _, _ := purego.SyscallN(e.funcs.CreateBitstreamBuffer, e.encoder, uintptr(unsafe.Pointer(&createBuf))); r != nvencSuccess {
		e.shutdownSession()
		return fmt.Errorf("NvEncCreateBitstreamBuffer failed: %s (0x%X)", nvencStatusStr(r), r)
	}
	e.bitstreamBuf = createBuf.Buffer

	// Step 7: CUDA device buffer for NV12 (Y: w*h, interleaved UV: w*h/2).
	e.cuBufSize = uint64(e.width*e.height) + uint64(e.width*e.height/2)
	if r, _, _ := purego.SyscallN(cuMemAllocPtr, uintptr(unsafe.Pointer(&e.cuInputDPtr)), uintptr(e.cuBufSize)); r != cudaSuccess {
		e.shutdownSession()
		return fmt.Errorf("cuMemAlloc(%d) failed: CUDA error %d", e.cuBufSize, r)
	}

	// Step 8: register the CUDA buffer as an NVENC input resource (once).
	var reg nvencRegisterResource
	reg.Version = nvencStructVer(5)
	reg.ResType = nvencInputResCUDA
	reg.Width = uint32(e.width)
	reg.Height = uint32(e.height)
	reg.Pitch = uint32(e.width) // NV12 luma pitch == width for a packed buffer
	reg.Resource = uintptr(e.cuInputDPtr)
	reg.BufFormat = nvencBufFmtNV12
	reg.BufUsage = nvencBufUsageInput
	if r, _, _ := purego.SyscallN(e.funcs.RegisterResource, e.encoder, uintptr(unsafe.Pointer(&reg))); r != nvencSuccess {
		e.shutdownSession()
		return fmt.Errorf("NvEncRegisterResource(CUDA) failed: %s (0x%X)", nvencStatusStr(r), r)
	}
	e.registeredRes = reg.Registered

	e.inited = true
	e.frameIdx = 0
	cfgSrc := "hand-built"
	if gotPreset {
		cfgSrc = "legacy-preset"
	}
	slog.Info("NVENC (Linux) encoder initialized",
		"width", e.width, "height", e.height, "fps", fps, "bitrate", bitrate,
		"preset", "LOW_LATENCY_HQ", "config", cfgSrc)
	return nil
}

// =============================================================================
// Per-frame encoding
// =============================================================================

func (e *nvencEncoderLinux) encodeFrame() ([]byte, error) {
	// Map the (already data-filled) CUDA input resource.
	var mapRes nvencMapInputResource
	mapRes.Version = nvencStructVer(4)
	mapRes.Registered = e.registeredRes
	if r, _, _ := purego.SyscallN(e.funcs.MapInputResource, e.encoder, uintptr(unsafe.Pointer(&mapRes))); r != nvencSuccess {
		return nil, fmt.Errorf("NvEncMapInputResource failed: %s (0x%X)", nvencStatusStr(r), r)
	}
	mappedHandle := mapRes.Mapped
	mappedFmt := mapRes.MappedFmt

	var picParams nvencPicParams
	picParams.Version = nvencStructVerExt(7)
	picParams.InputWidth = uint32(e.width)
	picParams.InputHeight = uint32(e.height)
	picParams.InputPitch = uint32(e.width)
	picParams.InputBuffer = mappedHandle
	picParams.OutputBitstream = e.bitstreamBuf
	picParams.BufferFmt = mappedFmt
	picParams.PictureStruct = nvencPicStructFrame
	picParams.FrameIdx = uint32(e.frameIdx)
	if e.forceIDR || e.frameIdx == 0 {
		picParams.EncodePicFlags = nvencPicFlagForceIDR | nvencPicFlagSPSPPS
		e.forceIDR = false
	}
	e.frameIdx++

	r, _, _ := purego.SyscallN(e.funcs.EncodePicture, e.encoder, uintptr(unsafe.Pointer(&picParams)))
	purego.SyscallN(e.funcs.UnmapInputResource, e.encoder, mappedHandle) // always unmap
	if r != nvencSuccess {
		return nil, fmt.Errorf("NvEncEncodePicture failed: %s (0x%X)", nvencStatusStr(r), r)
	}

	var lockBS nvencLockBitstream
	lockBS.Version = nvencStructVerExt(2)
	lockBS.OutputBitstream = e.bitstreamBuf
	if r, _, _ := purego.SyscallN(e.funcs.LockBitstream, e.encoder, uintptr(unsafe.Pointer(&lockBS))); r != nvencSuccess {
		return nil, fmt.Errorf("NvEncLockBitstream failed: %s (0x%X)", nvencStatusStr(r), r)
	}
	var out []byte
	if lockBS.BitstreamSize > 0 && lockBS.DataPtr != 0 {
		out = make([]byte, lockBS.BitstreamSize)
		// DataPtr is a C pointer NVENC stored in a uintptr field. Read it back as
		// an unsafe.Pointer by reinterpreting the field's bits, rather than
		// unsafe.Pointer(uintptr) directly, which `go vet` flags as a possible
		// misuse (the value isn't a Go-managed address the GC must track).
		dataPtr := *(*unsafe.Pointer)(unsafe.Pointer(&lockBS.DataPtr))
		copy(out, unsafe.Slice((*byte)(dataPtr), lockBS.BitstreamSize))
	}
	purego.SyscallN(e.funcs.UnlockBitstream, e.encoder, e.bitstreamBuf)

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// =============================================================================
// Shutdown
// =============================================================================

func (e *nvencEncoderLinux) shutdown() {
	wasInited := e.inited
	if e.registeredRes != 0 {
		purego.SyscallN(e.funcs.UnregisterResource, e.encoder, e.registeredRes)
		e.registeredRes = 0
	}
	e.shutdownSession()
	e.inited = false
	if wasInited {
		slog.Info("NVENC (Linux) encoder shut down")
	}
}

// shutdownSession tears down NVENC + CUDA resources. Safe to call partway
// through a failed initialize().
func (e *nvencEncoderLinux) shutdownSession() {
	if e.bitstreamBuf != 0 {
		purego.SyscallN(e.funcs.DestroyBitstreamBuffer, e.encoder, e.bitstreamBuf)
		e.bitstreamBuf = 0
	}
	if e.encoder != 0 {
		purego.SyscallN(e.funcs.DestroyEncoder, e.encoder)
		e.encoder = 0
	}
	e.destroyCUDA()
}

func (e *nvencEncoderLinux) destroyCUDA() {
	if e.cuCtx != 0 {
		// cuMemFree needs a current context; bind it before freeing.
		purego.SyscallN(cuCtxSetCurrentPtr, e.cuCtx)
	}
	if e.cuInputDPtr != 0 {
		purego.SyscallN(cuMemFreePtr, uintptr(e.cuInputDPtr))
		e.cuInputDPtr = 0
	}
	if e.cuCtx != 0 {
		purego.SyscallN(cuCtxDestroyPtr, e.cuCtx)
		e.cuCtx = 0
	}
}
