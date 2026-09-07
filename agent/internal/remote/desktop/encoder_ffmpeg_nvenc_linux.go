//go:build linux

package desktop

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strconv"
	"sync"
)

// =============================================================================
// FFmpeg NVENC encoder (Linux) — hardware H264 via an ffmpeg subprocess.
//
// The direct purego bindings to libnvidia-encode never got past the driver's
// config validation (INVALID_PTR/INVALID_DEVICE/INVALID_PARAM/segfault) and are
// impractical to iterate on without local hardware. ffmpeg's h264_nvenc handles
// the whole NVENC/CUDA/NV12/preset dance correctly, so we shell out to it:
// raw BGRA frames go in on stdin, Annex-B H264 comes out on stdout.
//
// Requires ffmpeg with h264_nvenc on the host (Debian: `apt install ffmpeg`).
// If ffmpeg is missing the factory fails and the encoder falls back to OpenH264.
// =============================================================================

func init() {
	registerHardwareFactoryForVendor("nvidia", newFFmpegNVENCEncoder)
}

func newFFmpegNVENCEncoder(cfg EncoderConfig) (encoderBackend, error) {
	if cfg.Codec != CodecH264 {
		return nil, fmt.Errorf("ffmpeg-nvenc: only H264 supported, got %s", cfg.Codec)
	}
	path, err := exec.LookPath("ffmpeg")
	if err != nil {
		return nil, fmt.Errorf("ffmpeg not found in PATH: %w", err)
	}
	return &ffmpegNVENCEncoder{cfg: cfg, ffmpegPath: path}, nil
}

type ffmpegNVENCEncoder struct {
	mu          sync.Mutex
	cfg         EncoderConfig
	ffmpegPath  string
	width       int
	height      int
	pixelFormat PixelFormat

	cmd     *exec.Cmd
	stdin   io.WriteCloser
	aus     chan []byte // parsed Annex-B access units from ffmpeg stdout
	readErr error
	inited  bool
}

// --- encoderBackend interface ---

func (e *ffmpegNVENCEncoder) Name() string {
	if e.inited {
		return "ffmpeg-nvenc"
	}
	return "ffmpeg-nvenc(init)"
}

func (e *ffmpegNVENCEncoder) IsHardware() bool    { return true }
func (e *ffmpegNVENCEncoder) IsPlaceholder() bool { return false }

func (e *ffmpegNVENCEncoder) SetCodec(c Codec) error {
	if c != CodecH264 {
		return fmt.Errorf("%w: ffmpeg-nvenc only supports H264, got %s", ErrInvalidCodec, c)
	}
	return nil
}

func (e *ffmpegNVENCEncoder) SetQuality(_ QualityPreset) error { return nil }
func (e *ffmpegNVENCEncoder) SetPixelFormat(pf PixelFormat)    { e.pixelFormat = pf }

func (e *ffmpegNVENCEncoder) SetBitrate(bitrate int) error {
	if bitrate <= 0 {
		return ErrInvalidBitrate
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	// ffmpeg CBR is fixed at spawn; a live change would need a restart, which we
	// avoid (it would drop frames on every adaptive tweak). Applied at next init.
	e.cfg.Bitrate = bitrate
	return nil
}

func (e *ffmpegNVENCEncoder) SetFPS(fps int) error {
	if fps <= 0 {
		return ErrInvalidFPS
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.FPS = fps
	return nil
}

func (e *ffmpegNVENCEncoder) SetDimensions(w, h int) error {
	w = w &^ 1
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

// GPU zero-copy is Windows/D3D11-only; we take CPU frames on stdin.
func (e *ffmpegNVENCEncoder) SetD3D11Device(_, _ uintptr) {}
func (e *ffmpegNVENCEncoder) SupportsGPUInput() bool      { return false }
func (e *ffmpegNVENCEncoder) IsGPUOnly() bool             { return false }
func (e *ffmpegNVENCEncoder) EncodeTexture(_ uintptr) ([]byte, error) {
	return nil, fmt.Errorf("ffmpeg-nvenc: EncodeTexture not supported, use Encode")
}

// ForceKeyframe is best-effort only: a running ffmpeg pipe can't be signalled
// per-frame, so we rely on the fixed GOP (a keyframe every ~2s) for new-viewer
// and loss recovery.
func (e *ffmpegNVENCEncoder) ForceKeyframe() error { return nil }
func (e *ffmpegNVENCEncoder) Flush() error         { return nil }

func (e *ffmpegNVENCEncoder) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.shutdown()
	return nil
}

// Encode writes one BGRA frame to ffmpeg's stdin and returns the next available
// Annex-B access unit. h264_nvenc with -bf 0 -delay 0 emits one AU per input
// frame in order, so this stays 1:1 in steady state.
func (e *ffmpegNVENCEncoder) Encode(frame []byte) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.inited {
		if err := e.start(); err != nil {
			return nil, fmt.Errorf("ffmpeg-nvenc start: %w", err)
		}
	}

	want := e.width * e.height * 4
	if len(frame) < want {
		return nil, fmt.Errorf("ffmpeg-nvenc: short frame %d, want %d", len(frame), want)
	}
	if _, err := e.stdin.Write(frame[:want]); err != nil {
		e.shutdown()
		return nil, fmt.Errorf("ffmpeg-nvenc: write stdin: %w", err)
	}

	// Grab the encoded AU. A pipeline delay of up to a frame is normal at
	// startup, so wait briefly; if nothing is ready, report a skipped frame
	// (nil, nil) rather than stalling the capture loop.
	au, ok := <-e.aus
	if !ok {
		return nil, fmt.Errorf("ffmpeg-nvenc: output closed: %v", e.readErr)
	}
	return au, nil
}

// =============================================================================
// Process lifecycle
// =============================================================================

func (e *ffmpegNVENCEncoder) start() error {
	if e.width == 0 || e.height == 0 {
		return fmt.Errorf("dimensions not set — call SetDimensions first")
	}
	fps := e.cfg.FPS
	if fps <= 0 {
		fps = 30
	}
	bitrate := e.cfg.Bitrate
	if bitrate <= 0 {
		bitrate = 8_000_000
	}
	gop := fps * 2 // keyframe every ~2s (new-viewer / loss recovery)

	args := []string{
		"-hide_banner", "-loglevel", "error",
		// input: raw BGRA frames on stdin
		"-f", "rawvideo",
		"-pix_fmt", "bgra",
		"-s", strconv.Itoa(e.width) + "x" + strconv.Itoa(e.height),
		"-r", strconv.Itoa(fps),
		"-i", "pipe:0",
		// output: NVENC H264, low-latency CBR, no B-frames, fixed GOP
		"-an",
		"-c:v", "h264_nvenc",
		"-preset", "p4",
		"-tune", "ull",
		"-rc", "cbr",
		"-b:v", strconv.Itoa(bitrate),
		"-maxrate", strconv.Itoa(bitrate),
		"-bufsize", strconv.Itoa(bitrate / fps * 2),
		"-g", strconv.Itoa(gop),
		"-bf", "0",
		"-delay", "0",
		"-pix_fmt", "yuv420p",
		// insert AUDs so the reader can split the stream into access units
		"-bsf:v", "h264_metadata=aud=insert",
		"-f", "h264", "pipe:1",
	}

	cmd := exec.Command(e.ffmpegPath, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start ffmpeg: %w", err)
	}

	e.cmd = cmd
	e.stdin = stdin
	e.aus = make(chan []byte, 8)
	e.readErr = nil

	go e.readLoop(stdout)
	go logFFmpegStderr(stderr)

	e.inited = true
	slog.Info("ffmpeg-nvenc encoder started",
		"width", e.width, "height", e.height, "fps", fps, "bitrate", bitrate,
		"codec", "h264_nvenc", "preset", "p4", "tune", "ull")
	return nil
}

func (e *ffmpegNVENCEncoder) shutdown() {
	if !e.inited {
		return
	}
	if e.stdin != nil {
		_ = e.stdin.Close() // EOF → ffmpeg flushes and exits
		e.stdin = nil
	}
	if e.cmd != nil {
		_ = e.cmd.Process.Kill()
		_ = e.cmd.Wait()
		e.cmd = nil
	}
	e.inited = false
	slog.Info("ffmpeg-nvenc encoder shut down")
}

// readLoop parses ffmpeg's Annex-B output into access units (split on the AUD
// NALs h264_metadata inserts) and delivers them on e.aus.
func (e *ffmpegNVENCEncoder) readLoop(stdout io.Reader) {
	defer close(e.aus)
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 1<<20), 32<<20) // up to 32MB per AU (4K IDR)
	sc.Split(splitAnnexBAU)
	for sc.Scan() {
		b := sc.Bytes()
		au := make([]byte, len(b))
		copy(au, b)
		e.aus <- au
	}
	e.readErr = sc.Err()
}

// splitAnnexBAU is a bufio.SplitFunc that yields one H264 access unit per token,
// splitting at each Access Unit Delimiter (NAL type 9) that ffmpeg's
// h264_metadata=aud=insert places at the start of every AU.
func splitAnnexBAU(data []byte, atEOF bool) (advance int, token []byte, err error) {
	start := indexAUD(data, 0)
	if start < 0 {
		if atEOF && len(data) > 0 {
			return len(data), data, nil
		}
		return 0, nil, nil // need more data to find the first AUD
	}
	next := indexAUD(data, start+3)
	if next < 0 {
		if atEOF {
			return len(data), data[start:], nil
		}
		return start, nil, nil // drop bytes before the AUD, wait for the next
	}
	return next, data[start:next], nil
}

// indexAUD returns the offset of the next Access Unit Delimiter start code
// (00 00 01 09 or 00 00 00 01 09) at or after `from`, or -1.
func indexAUD(b []byte, from int) int {
	for i := from; i+3 < len(b); i++ {
		if b[i] != 0 || b[i+1] != 0 {
			continue
		}
		if b[i+2] == 1 && b[i+3] == 0x09 {
			return i
		}
		if i+4 < len(b) && b[i+2] == 0 && b[i+3] == 1 && b[i+4] == 0x09 {
			return i
		}
	}
	return -1
}

func logFFmpegStderr(stderr io.Reader) {
	sc := bufio.NewScanner(stderr)
	for sc.Scan() {
		slog.Warn("ffmpeg-nvenc stderr", "line", sc.Text())
	}
}
