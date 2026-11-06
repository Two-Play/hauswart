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
		// Not the temporary directory: anyone could put a socket there first.
		if home, err := os.UserHomeDir(); err == nil {
			dir = home
		}
	}
	return filepath.Join(dir, ".hauswart-tray.sock")
}

// Running says whether the app runs already, and asks it to open its window, which
// is what the launcher in the menu does on a desktop without a tray. It comes before
// anything else: the tray allows only one app of a name per session.
func Running() bool {
	conn, err := net.Dial("unix", socketPath())
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Listen waits for later starts, for as long as this one runs.
func Listen(show func()) {
	path := socketPath()
	os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return // then a second start opens a second app, which is no harm
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
}
