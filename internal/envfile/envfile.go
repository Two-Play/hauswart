// Package envfile reads settings that hold secrets, in KEY=value lines.
package envfile

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	privateBits = 0o077
	maxSize     = 64 << 10
)

// Read hands each setting to set, which says whether it knows the key. A missing
// file is not an error and reports false. Anything else that is wrong is one,
// because a typo should not silently end a feature, and neither should
// credentials be used from a file others can read. Values stay out of every
// error, because they may be secrets.
func Read(path string, set func(key, value string) bool) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode().Perm()&privateBits != 0 {
		return false, fmt.Errorf("%s has mode %04o, it must be 0600", path, info.Mode().Perm())
	}
	if info.Size() > maxSize {
		return false, fmt.Errorf("%s is too large", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok {
			return false, fmt.Errorf("%s:%d: expected KEY=value", path, line)
		}
		if !set(strings.TrimSpace(key), unquote(strings.TrimSpace(value))) {
			return false, fmt.Errorf("%s:%d: unknown setting %q", path, line, strings.TrimSpace(key))
		}
	}
	return true, scanner.Err()
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}
