//go:build !windows

package main

import (
	"fmt"
	"os"
)

// breeze-etwprobe is a Windows-only ETW diagnostic (see main_windows.go).
func main() {
	fmt.Fprintln(os.Stderr, "breeze-etwprobe is Windows-only (ETW). Build/run it on Windows: GOOS=windows go build ./cmd/breeze-etwprobe")
	os.Exit(1)
}
