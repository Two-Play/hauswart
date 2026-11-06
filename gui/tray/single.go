package tray

import (
	"net"
	"os"
	"path/filepath"
)

// socketPath is private to the person running this.
func socketPath() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "hauswart-tray.sock")
}

// Single makes sure that one app runs per person. A second start only asks the
// first to open its window, which is what the launcher in the menu does on a
// desktop without a tray. It returns false if another one is running.
func Single(show func()) bool {
	path := socketPath()
	if conn, err := net.Dial("unix", path); err == nil {
		conn.Close()
		return false
	}
	os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return true // better two apps than none
	}
	os.Chmod(path, 0o600)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
			show()
		}
	}()
	return true
}
