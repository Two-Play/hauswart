package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/Two-Play/hauswart/internal/api"
)

// A full-screen block runs hauswart-blocker in the kiosk compositor cage, as a
// system service on a console of its own. It belongs to a system account, not to
// anyone at the device, so nobody there can end it. cage may switch consoles,
// so that others reach the login screen while a block is about one person; the
// agent brings the block back to whoever it is about, and locks their sessions.
const (
	blockUnit    = "hauswart-block.service"
	blockUser    = "hauswart-block"
	blockTTY     = "tty9"
	blockDir     = "/run/hauswart/block"
	blockProgram = "hauswart-blocker"
	unitPath     = "/etc/systemd/system/" + blockUnit
	pamPath      = "/etc/pam.d/hauswart-block"
	// activeTTY names the console in front.
	activeTTY = "/sys/class/tty/tty0/active"
)

// blockUnitText starts cage on its console with a session of its own, which
// gives it the screen and the input while that console is in front.
const blockUnitText = `# Managed by Hauswart
[Unit]
Description=Hauswart full-screen block
After=systemd-user-sessions.service hauswart-agent.service
Conflicts=getty@` + blockTTY + `.service
# Without the agent nobody would end the block, so it ends with the agent.
BindsTo=hauswart-agent.service

[Service]
User=` + blockUser + `
PAMName=hauswart-block
TTYPath=/dev/` + blockTTY + `
TTYReset=yes
TTYVHangup=yes
TTYVTDisallocate=yes
StandardInput=tty-fail
StandardOutput=journal
StandardError=journal
UtmpIdentifier=` + blockTTY + `
UtmpMode=user
Environment=XDG_SESSION_TYPE=wayland
ExecStart=/usr/bin/cage -s -- /usr/bin/` + blockProgram + `
Restart=always
RestartSec=1
`

// blockPAMText opens a logind session for the account. systemd runs no auth for
// PAMName, so auth refuses everyone: nothing else may log in through this name.
const blockPAMText = `# Managed by Hauswart
auth     required pam_deny.so
account  required pam_permit.so
session  required pam_systemd.so
`

// prepareFullscreen makes sure everything a full-screen block needs is there.
// It runs when the block is set, so that a missing part fails the task.
func (e *Executor) prepareFullscreen(ctx context.Context, p api.AccessPayload) error {
	if e.Has != nil && !e.Has(blockProgram) {
		return errors.New("hauswart-blocker is missing: install the package hauswart-tray on this device")
	}
	if e.Has != nil && !e.Has("cage") {
		unlock := e.lockPackages()
		err := e.installPackage(ctx, "cage")
		unlock()
		if err != nil {
			return err
		}
	}
	if _, err := user.Lookup(blockUser); err != nil {
		if out, err := e.Run(ctx, "useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent",
			"--shell", "/usr/sbin/nologin", "--", blockUser); err != nil {
			return fmt.Errorf("creating the account of the block failed: %w: %s", err, clip(out, maxDeviationText))
		}
	}
	changed := false
	for path, text := range map[string]string{unitPath: blockUnitText, pamPath: blockPAMText} {
		full := e.path(path)
		if current, err := os.ReadFile(full); err == nil && string(current) == text {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := writeAtomic(full, []byte(text), 0o644); err != nil {
			return err
		}
		changed = true
	}
	if changed {
		if out, err := e.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return fmt.Errorf("%w: %s", err, clip(out, maxDeviationText))
		}
	}
	return nil
}

// writeBlockContent leaves the message and the picture for hauswart-blocker.
func (e *Executor) writeBlockContent(p api.AccessPayload) error {
	dir := e.path(blockDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, "message"), []byte(p.Message+"\n"), 0o644); err != nil {
		return err
	}
	picture := filepath.Join(dir, "image")
	if p.Image == "" {
		if err := os.Remove(picture); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	raw, err := api.AccessImage(p.Image)
	if err != nil {
		return err
	}
	return writeAtomic(picture, raw, 0o644)
}

// installPackage installs one package through the package manager of the device.
// The caller holds the package lock.
func (e *Executor) installPackage(ctx context.Context, name string) error {
	if e.Platform.Backend == nil {
		return fmt.Errorf("%s is missing, and no package manager can install it", name)
	}
	if refresh := e.Platform.Backend.Refresh; refresh != nil {
		e.Run(ctx, refresh[0], refresh[1:]...)
	}
	argv := e.Platform.Backend.Install([]string{name})
	if out, err := e.Run(ctx, argv[0], argv[1:]...); err != nil {
		return fmt.Errorf("installing %s failed: %w: %s", name, err, clip(out, maxDeviationText))
	}
	return nil
}

// frontTTY says which console is in front, such as tty2.
func (e *Executor) frontTTY() string {
	raw, err := os.ReadFile(e.path(activeTTY))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// showBlock starts the block if it is not running and brings its console to the
// front. It returns the console that was in front before, to go back to later.
func (a *Access) showBlock(ctx context.Context) {
	if out, err := a.exec.Run(ctx, "systemctl", "is-active", "--quiet", blockUnit); err != nil {
		if out, err := a.exec.Run(ctx, "systemctl", "start", blockUnit); err != nil {
			a.log.Warn("starting the full-screen block failed", "err", err, "output", clip(out, maxDeviationText))
			return
		}
		_ = out
	}
	a.mu.Lock()
	a.shown = true
	a.mu.Unlock()
	front := a.exec.frontTTY()
	if front == blockTTY || front == "" {
		return
	}
	a.mu.Lock()
	a.returnTo = front
	a.mu.Unlock()
	if out, err := a.exec.Run(ctx, "chvt", strings.TrimPrefix(blockTTY, "tty")); err != nil {
		a.log.Warn("switching to the full-screen block failed", "err", err, "output", clip(out, maxDeviationText))
	}
}

// hideBlock stops the block and goes back to the console that was in front.
func (a *Access) hideBlock(ctx context.Context) {
	a.mu.Lock()
	shown := a.shown
	a.shown = false
	a.mu.Unlock()
	if !shown {
		return
	}
	if out, err := a.exec.Run(ctx, "systemctl", "stop", blockUnit); err != nil {
		a.log.Warn("stopping the full-screen block failed", "err", err, "output", clip(out, maxDeviationText))
	}
	a.mu.Lock()
	back := a.returnTo
	a.returnTo = ""
	a.mu.Unlock()
	if back != "" && a.exec.frontTTY() == blockTTY {
		a.exec.Run(ctx, "chvt", strings.TrimPrefix(back, "tty"))
	}
}

// activeUser is who uses the session in front on seat0, empty if nobody does.
func (e *Executor) activeUser(ctx context.Context) string {
	out, err := e.Run(ctx, "loginctl", "show-seat", "seat0", "-p", "ActiveSession", "--value")
	session := strings.TrimSpace(out)
	if err != nil || !sessionIDRe.MatchString(session) {
		return ""
	}
	out, err = e.Run(ctx, "loginctl", "show-session", session, "-p", "Name", "--value")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}
