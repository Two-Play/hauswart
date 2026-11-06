package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/Two-Play/hauswart/internal/api"
)

const (
	firewallD   = "firewalld"
	firewallUFW = "ufw"

	checkOn      = "on"
	checkOff     = "off"
	checkUnknown = "unknown"
)

// enforceSecurity turns the firewall on and looks at what cannot be enforced. A
// result of unknown is not a deviation: the check tells what it could not see.
func (pe *PolicyEngine) enforceSecurity(ctx context.Context, rule *api.SecurityRule, o *outcome) map[string]string {
	if rule == nil {
		return nil
	}
	e := pe.exec
	checks := map[string]string{}
	if rule.Firewall {
		checks["firewall"] = e.enforceFirewall(ctx, o)
	}
	if rule.DiskEncryption {
		checks["disk_encryption"] = e.diskEncryption(ctx)
		if checks["disk_encryption"] == checkOff {
			o.deviate(deviationSecure, "disk encryption", "the root file system is not encrypted")
		}
	}
	if rule.ScreenLock {
		state, users := e.screenLock(ctx)
		checks["screen_lock"] = state
		if state == checkOff {
			o.deviate(deviationSecure, "screen lock", "off for "+strings.Join(users, ", "))
		}
	}
	return checks
}

func (e *Executor) enforceFirewall(ctx context.Context, o *outcome) string {
	firewall := e.Platform.Firewall
	if firewall == "" && e.Has != nil {
		firewall = detectFirewall(e.Has) // a required package may have brought it
	}
	switch firewall {
	case firewallD:
		if _, err := e.Run(ctx, "systemctl", "is-active", "--quiet", firewallD); err == nil {
			return checkOn
		}
		if out, err := e.Run(ctx, "systemctl", "enable", "--now", firewallD); err != nil {
			o.deviate(deviationSecure, "firewall", strings.TrimSpace(out+" "+err.Error()))
			return checkOff
		}
	case firewallUFW:
		if out, err := e.Run(ctx, "ufw", "status"); err == nil && strings.Contains(out, "Status: active") {
			return checkOn
		}
		// ufw starts by refusing everything from outside, which would cut off
		// an admin who is on this device right now. Whether sshd runs says
		// nothing, because socket activation starts it at the first connection.
		for _, port := range e.sshPorts(ctx) {
			if out, err := e.Run(ctx, "ufw", "allow", port+"/tcp"); err != nil {
				o.deviate(deviationSecure, "firewall", strings.TrimSpace(out+" "+err.Error()))
				return checkOff
			}
		}
		if out, err := e.Run(ctx, "ufw", "--force", "enable"); err != nil {
			o.deviate(deviationSecure, "firewall", strings.TrimSpace(out+" "+err.Error()))
			return checkOff
		}
	default:
		// Installing one is up to the admin, through required packages.
		o.deviate(deviationSecure, "firewall", "neither firewalld nor ufw is installed")
		return checkOff
	}
	o.corrected = append(o.corrected, "firewall")
	return checkOn
}

// sshPorts asks sshd for its configuration. Opening a port nothing listens on
// costs nothing, so the default stands if there is no answer.
func (e *Executor) sshPorts(ctx context.Context) []string {
	var ports []string
	if out, err := e.Run(ctx, "sshd", "-T"); err == nil {
		for line := range strings.Lines(out) {
			if port, ok := strings.CutPrefix(strings.TrimSpace(line), "port "); ok && portRe.MatchString(port) {
				ports = append(ports, port)
			}
		}
	}
	if len(ports) == 0 {
		return []string{"22"}
	}
	return ports
}

var portRe = regexp.MustCompile(`^[0-9]{1,5}$`)

// A subvolume shows up behind the device, as in /dev/mapper/root[/home].
var subvolumeRe = regexp.MustCompile(`\[.*\]$`)

// diskEncryption follows the root file system down its stack of devices. Below a
// file system on LVM on LUKS, lsblk lists all of them.
func (e *Executor) diskEncryption(ctx context.Context) string {
	out, err := e.Run(ctx, "findmnt", "-no", "SOURCE", "/")
	source := subvolumeRe.ReplaceAllString(strings.TrimSpace(out), "")
	if err != nil || !strings.HasPrefix(source, "/dev/") {
		return checkUnknown
	}
	out, err = e.Run(ctx, "lsblk", "-s", "-no", "TYPE", source)
	if err != nil {
		return checkUnknown
	}
	for _, kind := range strings.Fields(out) {
		if kind == "crypt" {
			return checkOn
		}
	}
	return checkOff
}

// screenLock asks the running sessions, since the setting belongs to each user.
// Without a session or on another desktop nobody can tell.
func (e *Executor) screenLock(ctx context.Context) (string, []string) {
	sessions, err := e.graphicalSessions(ctx)
	if err != nil {
		return checkUnknown, nil
	}
	state := checkUnknown
	var off []string
	for _, session := range sessions {
		switch e.sessionLock(ctx, session) {
		case checkOff:
			off = append(off, session.person.Username)
			state = checkOff
		case checkOn:
			if state == checkUnknown {
				state = checkOn
			}
		}
	}
	return state, off
}

func (e *Executor) sessionLock(ctx context.Context, session graphicalSession) string {
	desktop := strings.ToLower(session.desktop)
	switch {
	case strings.Contains(desktop, "gnome") || e.running(ctx, session, "gnome-shell"):
		return e.gnomeLock(ctx, session)
	case strings.Contains(desktop, "kde") || strings.Contains(desktop, "plasma") || e.running(ctx, session, "plasmashell"):
		return kdeLock(e.path(filepath.Join(session.person.HomeDir, ".config", "kscreenlockerrc")))
	}
	return checkUnknown
}

// running looks for a program of the session's user. A session started by an
// automatic login may not name its desktop at all.
func (e *Executor) running(ctx context.Context, session graphicalSession, program string) bool {
	_, err := e.Run(ctx, "pgrep", "-x", "-u", session.person.Uid, program)
	return err == nil
}

func (e *Executor) gnomeLock(ctx context.Context, session graphicalSession) string {
	get := func(schema, key string) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, popupTimeout)
		defer cancel()
		out, err := e.Run(ctx, "runuser", "-u", session.person.Username, "--",
			"env", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/"+session.person.Uid+"/bus",
			"gsettings", "get", schema, key)
		return strings.TrimSpace(out), err
	}
	enabled, err := get("org.gnome.desktop.screensaver", "lock-enabled")
	if err != nil {
		return checkUnknown
	}
	idle, err := get("org.gnome.desktop.session", "idle-delay")
	if err != nil {
		return checkUnknown
	}
	// Without an idle time the screen never blanks, and so it never locks.
	if enabled != "true" || idle == "uint32 0" {
		return checkOff
	}
	return checkOn
}

// kdeLock reads the file directly, as Plasma only writes what differs from the
// default of locking automatically.
func kdeLock(path string) string {
	raw, err := readUserFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return checkOn
	}
	if err != nil {
		return checkUnknown
	}
	section := ""
	for line := range strings.Lines(string(raw)) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		if section == "[Daemon]" && strings.EqualFold(line, "Autolock=false") {
			return checkOff
		}
	}
	return checkOn
}

// maxUserFile is far more than any settings file a check reads.
const maxUserFile = 64 << 10

// readUserFile reads a file in someone's home directory as root. Its owner
// decides what is at that path, so a link, a pipe that never answers or an endless
// device must not reach the agent.
func readUserFile(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return io.ReadAll(io.LimitReader(file, maxUserFile))
}
