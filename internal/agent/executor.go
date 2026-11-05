package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/philippe/hauswart/internal/api"
	"github.com/philippe/hauswart/internal/pki"
)

const (
	taskTimeout = 30 * time.Minute
	maxOutput   = 64 << 10
	minUserUID  = 1000
)

// Executor applies tasks to the system. Root is prepended to every path it
// touches, which lets tests run against a temporary directory.
type Executor struct {
	Root         string
	AllowedPaths []string
	Platform     Platform
	Grants       *GrantStore
	// Run executes a command and returns its combined output.
	Run func(ctx context.Context, name string, args ...string) (string, error)
	// RunInput is Run with data on stdin, for values that must stay out of
	// the process list.
	RunInput func(ctx context.Context, input, name string, args ...string) (string, error)
}

func (e *Executor) path(p string) string { return filepath.Join(e.Root, p) }

// Execute validates again, regardless of what the server claims to have
// checked: this is the last line of defence on a device running as root.
func (e *Executor) Execute(ctx context.Context, t api.Task) api.TaskResult {
	ctx, cancel := context.WithTimeout(ctx, taskTimeout)
	defer cancel()

	out, err := e.dispatch(ctx, t)
	if len(out) > maxOutput {
		out = out[len(out)-maxOutput:]
	}
	if err != nil {
		return api.TaskResult{OK: false, Output: strings.TrimSpace(out + "\n" + err.Error())}
	}
	return api.TaskResult{OK: true, Output: out}
}

func (e *Executor) dispatch(ctx context.Context, t api.Task) (string, error) {
	if err := api.Validate(t.Type, t.Payload); err != nil {
		return "", err
	}
	switch t.Type {
	case api.TaskPkgInstall, api.TaskPkgRemove, api.TaskFlatpakInstall:
		var p api.PackagesPayload
		if err := json.Unmarshal(t.Payload, &p); err != nil {
			return "", err
		}
		return e.packages(ctx, t.Type, p.Packages)
	case api.TaskPkgUpgrade:
		return e.packages(ctx, t.Type, nil)
	case api.TaskFilePut:
		var p api.FilePutPayload
		if err := json.Unmarshal(t.Payload, &p); err != nil {
			return "", err
		}
		return e.filePut(p)
	case api.TaskCAInstall:
		var p api.CAInstallPayload
		if err := json.Unmarshal(t.Payload, &p); err != nil {
			return "", err
		}
		return e.caInstall(ctx, p)
	case api.TaskSudoGrant:
		var p api.SudoGrantPayload
		if err := json.Unmarshal(t.Payload, &p); err != nil {
			return "", err
		}
		return e.sudoGrant(ctx, p)
	case api.TaskSudoRevoke:
		var p api.UserPayload
		if err := json.Unmarshal(t.Payload, &p); err != nil {
			return "", err
		}
		return e.sudoRevoke(p.User)
	case api.TaskUserCreate:
		var p api.UserPayload
		if err := json.Unmarshal(t.Payload, &p); err != nil {
			return "", err
		}
		return e.userCreate(ctx, p)
	case api.TaskUserLock, api.TaskUserUnlock:
		var p api.UserPayload
		if err := json.Unmarshal(t.Payload, &p); err != nil {
			return "", err
		}
		return e.userLock(ctx, p.User, t.Type == api.TaskUserLock)
	case api.TaskUserPassword:
		var p api.PasswordPayload
		if err := json.Unmarshal(t.Payload, &p); err != nil {
			return "", err
		}
		return e.userPassword(ctx, p)
	case api.TaskLimitSet:
		var p api.LimitPayload
		if err := json.Unmarshal(t.Payload, &p); err != nil {
			return "", err
		}
		return e.limitSet(ctx, p)
	}
	return "", fmt.Errorf("task type %q not implemented", t.Type)
}

func (e *Executor) packages(ctx context.Context, taskType string, names []string) (string, error) {
	if taskType == api.TaskFlatpakInstall {
		if !e.Platform.Flatpak {
			return "", errors.New("flatpak is not installed")
		}
		return e.Run(ctx, "flatpak", append([]string{"install", "--system", "--noninteractive", "-y", "flathub", "--"}, names...)...)
	}
	if e.Platform.Backend == nil {
		return "", errors.New("no supported package manager found")
	}
	var argv []string
	switch taskType {
	case api.TaskPkgInstall:
		argv = e.Platform.Backend.Install(names)
	case api.TaskPkgRemove:
		argv = e.Platform.Backend.Remove(names)
	default:
		argv = e.Platform.Backend.Upgrade()
	}
	return e.Run(ctx, argv[0], argv[1:]...)
}

// filePut writes only below the locally configured allowed paths. The list
// lives on the device, so the server cannot widen it. Without this limit,
// writing files as root would amount to arbitrary code execution.
func (e *Executor) filePut(p api.FilePutPayload) (string, error) {
	target := filepath.Clean(p.Path)
	dir, err := e.resolveExistingParent(filepath.Dir(target))
	if err != nil {
		return "", err
	}
	if !e.allowed(dir) {
		return "", fmt.Errorf("path %s is outside the allowed paths %v", target, e.AllowedPaths)
	}
	full := e.path(target)
	if info, err := os.Lstat(full); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing to write through symlink %s", target)
	}
	mode := os.FileMode(0o644)
	if p.Mode != "" {
		m, err := strconv.ParseUint(p.Mode, 8, 32)
		if err != nil {
			return "", err
		}
		mode = os.FileMode(m)
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return "", err
	}
	if err := writeAtomic(full, []byte(p.Content), mode); err != nil {
		return "", err
	}
	return "wrote " + target, nil
}

// resolveExistingParent follows symlinks in the part of dir that exists, so
// a symlink inside an allowed directory cannot lead out of it.
func (e *Executor) resolveExistingParent(dir string) (string, error) {
	root, err := filepath.EvalSymlinks(e.path("/"))
	if err != nil {
		return "", err
	}
	missing := ""
	for current := dir; ; current = filepath.Dir(current) {
		resolved, err := filepath.EvalSymlinks(e.path(current))
		if err == nil {
			rel, err := filepath.Rel(root, resolved)
			if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
				return "", fmt.Errorf("path %s leaves the root", dir)
			}
			return filepath.Join("/", rel, missing), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if current == "/" {
			return "", fmt.Errorf("cannot resolve %s", dir)
		}
		missing = filepath.Join(filepath.Base(current), missing)
	}
}

func (e *Executor) allowed(dir string) bool {
	for _, prefix := range e.AllowedPaths {
		base := filepath.Clean(prefix)
		if dir == base || strings.HasPrefix(dir, base+"/") {
			return true
		}
	}
	return false
}

func (e *Executor) caInstall(ctx context.Context, p api.CAInstallPayload) (string, error) {
	if _, err := pki.ParseCert([]byte(p.PEM)); err != nil {
		return "", err
	}
	if e.Platform.Trust == nil {
		return "", errors.New("no supported trust store found")
	}
	dir := e.path(e.Platform.Trust.Dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := "hauswart-" + p.Name + ".crt"
	if err := writeAtomic(filepath.Join(dir, name), []byte(p.PEM), 0o644); err != nil {
		return "", err
	}
	argv := e.Platform.Trust.Update
	return e.Run(ctx, argv[0], argv[1:]...)
}

func sudoersFile(user string) string { return "/etc/sudoers.d/hauswart-" + user }

func (e *Executor) sudoGrant(ctx context.Context, p api.SudoGrantPayload) (string, error) {
	if !time.Now().Before(p.ExpiresAt) {
		return "", errors.New("grant has already expired")
	}
	if _, err := e.lookupUser(p.User); err != nil {
		return "", err
	}
	rule := "ALL"
	if len(p.Commands) > 0 {
		rule = strings.Join(p.Commands, ", ")
	}
	content := fmt.Sprintf("# Managed by Hauswart, expires %s\n%s ALL=(ALL:ALL) %s\n",
		p.ExpiresAt.Format(time.RFC3339), p.User, rule)

	// sudo ignores files with a dot in their name, so a broken temporary file
	// can never lock everyone out of sudo.
	target := e.path(sudoersFile(p.User))
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return "", err
	}
	tmp := filepath.Join(filepath.Dir(target), ".hauswart-"+p.User+".tmp")
	if err := os.WriteFile(tmp, []byte(content), 0o440); err != nil {
		return "", err
	}
	defer os.Remove(tmp)
	if out, err := e.Run(ctx, "visudo", "-cf", tmp); err != nil {
		return out, fmt.Errorf("visudo rejected the rule: %w", err)
	}
	// Record the expiry first: a crash between the two steps then leaves a
	// harmless entry, never a rule that nothing will remove.
	if err := e.Grants.Set(p.User, p.ExpiresAt); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, target); err != nil {
		return "", err
	}
	return "sudo granted to " + p.User + " until " + p.ExpiresAt.Format(time.RFC3339), nil
}

func (e *Executor) sudoRevoke(user string) (string, error) {
	if err := os.Remove(e.path(sudoersFile(user))); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := e.Grants.Delete(user); err != nil {
		return "", err
	}
	return "sudo revoked for " + user, nil
}

// RevokeExpired removes every grant past its expiry. The agent does this on
// its own, so a grant ends on time even if the server is unreachable.
func (e *Executor) RevokeExpired() error {
	var errs []error
	for _, user := range e.Grants.Expired(time.Now()) {
		if _, err := e.sudoRevoke(user); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (e *Executor) userCreate(ctx context.Context, p api.UserPayload) (string, error) {
	args := []string{"--create-home"}
	if p.FullName != "" {
		args = append(args, "--comment", p.FullName)
	}
	if len(p.Groups) > 0 {
		args = append(args, "--groups", strings.Join(p.Groups, ","))
	}
	return e.Run(ctx, "useradd", append(args, "--", p.User)...)
}

func (e *Executor) userLock(ctx context.Context, name string, lock bool) (string, error) {
	u, err := e.lookupUser(name)
	if err != nil {
		return "", err
	}
	if uid, _ := strconv.Atoi(u.Uid); uid < minUserUID {
		return "", fmt.Errorf("refusing to change system account %s", name)
	}
	flag := "--unlock"
	if lock {
		flag = "--lock"
	}
	return e.Run(ctx, "usermod", flag, "--", name)
}

// userPassword sets a start password and expires it at once, so the user has
// to choose an own one at the first login.
func (e *Executor) userPassword(ctx context.Context, p api.PasswordPayload) (string, error) {
	u, err := e.lookupUser(p.User)
	if err != nil {
		return "", err
	}
	if uid, _ := strconv.Atoi(u.Uid); uid < minUserUID {
		return "", fmt.Errorf("refusing to change system account %s", p.User)
	}
	if out, err := e.RunInput(ctx, p.User+":"+p.Hash+"\n", "chpasswd", "-e"); err != nil {
		return out, err
	}
	if out, err := e.Run(ctx, "chage", "-d", "0", "--", p.User); err != nil {
		return out, err
	}
	return "start password set for " + p.User, nil
}

// limitSet uses a drop-in for the user's slice, which needs systemd but works
// the same on every systemd distribution.
func (e *Executor) limitSet(ctx context.Context, p api.LimitPayload) (string, error) {
	u, err := e.lookupUser(p.User)
	if err != nil {
		return "", err
	}
	if uid, _ := strconv.Atoi(u.Uid); uid < minUserUID {
		return "", fmt.Errorf("refusing to limit system account %s", p.User)
	}
	var b strings.Builder
	b.WriteString("# Managed by Hauswart\n[Slice]\n")
	if p.CPUPercent > 0 {
		fmt.Fprintf(&b, "CPUQuota=%d%%\n", p.CPUPercent)
	}
	if p.MemoryMB > 0 {
		fmt.Fprintf(&b, "MemoryMax=%dM\n", p.MemoryMB)
	}
	dir := e.path(fmt.Sprintf("/etc/systemd/system/user-%s.slice.d", u.Uid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := writeAtomic(filepath.Join(dir, "50-hauswart.conf"), []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	return e.Run(ctx, "systemctl", "daemon-reload")
}

func (e *Executor) lookupUser(name string) (*user.User, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("user %s does not exist on this device", name)
	}
	return u, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hauswart-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// RunCommand is the production implementation of Executor.Run.
func RunCommand(ctx context.Context, name string, args ...string) (string, error) {
	return RunCommandInput(ctx, "", name, args...)
}

// RunCommandInput is the production implementation of Executor.RunInput.
func RunCommandInput(ctx context.Context, input, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive")
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
