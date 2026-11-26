package auditor

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const MaxConfigBytes = 1024 * 1024 // 1 MiB cap for static inputs and configs

func readBoundedText(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat %q: %w", path, err)
	}
	if info.Size() > MaxConfigBytes {
		return "", fmt.Errorf("file %q exceeds %d byte limit", path, MaxConfigBytes)
	}

	raw, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return "", fmt.Errorf("read %q: %w", path, err)
	}
	if len(raw) > MaxConfigBytes {
		return "", fmt.Errorf("file %q exceeds %d byte limit", path, MaxConfigBytes)
	}
	return string(raw), nil
}

func normalizePath(path string) string {
	return strings.ReplaceAll(path, `\`, "/")
}
