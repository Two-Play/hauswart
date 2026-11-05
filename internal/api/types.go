// Package api holds the wire types shared by server and agent, plus the
// validation rules for every task. Both sides validate: the server to give
// early feedback, the agent because it is the actual enforcement boundary.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Task types. The agent executes only these; there is deliberately no
// "run arbitrary command" task.
const (
	TaskPkgInstall     = "pkg.install"
	TaskPkgRemove      = "pkg.remove"
	TaskPkgUpgrade     = "pkg.upgrade"
	TaskFlatpakInstall = "flatpak.install"
	TaskFilePut        = "file.put"
	TaskCAInstall      = "ca.install"
	TaskSudoGrant      = "sudo.grant"
	TaskSudoRevoke     = "sudo.revoke"
	TaskUserCreate     = "user.create"
	TaskUserLock       = "user.lock"
	TaskUserUnlock     = "user.unlock"
	TaskUserPassword   = "user.passwd"
	TaskLimitSet       = "limit.set"
)

type Task struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type TaskResult struct {
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

type PackagesPayload struct {
	Packages []string `json:"packages"`
}

type FilePutPayload struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    string `json:"mode"` // octal, e.g. "0644"
}

type CAInstallPayload struct {
	Name string `json:"name"`
	PEM  string `json:"pem"`
}

type SudoGrantPayload struct {
	User      string    `json:"user"`
	ExpiresAt time.Time `json:"expires_at"`
	// Commands limits the grant to absolute paths. Empty means all commands.
	Commands []string `json:"commands,omitempty"`
}

type UserPayload struct {
	User     string   `json:"user"`
	FullName string   `json:"full_name,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}

// PasswordPayload carries a crypt(3) hash, never a clear text password.
type PasswordPayload struct {
	User string `json:"user"`
	Hash string `json:"hash"`
}

type LimitPayload struct {
	User       string `json:"user"`
	CPUPercent int    `json:"cpu_percent,omitempty"` // 100 = one core
	MemoryMB   int    `json:"memory_mb,omitempty"`
}

// Report is the periodic inventory and health snapshot from an agent.
type Report struct {
	Hostname     string   `json:"hostname"`
	Distro       string   `json:"distro"`
	Kernel       string   `json:"kernel"`
	Backends     []string `json:"backends"`
	AgentVersion string   `json:"agent_version"`
	Uptime       int64    `json:"uptime_s"`
	Load1        float64  `json:"load1"`
	CPUs         int      `json:"cpus"`
	MemTotal     uint64   `json:"mem_total"`
	MemUsed      uint64   `json:"mem_used"`
	DiskTotal    uint64   `json:"disk_total"`
	DiskUsed     uint64   `json:"disk_used"`
}

type EnrollRequest struct {
	Token    string `json:"token"`
	CSR      string `json:"csr"`
	Hostname string `json:"hostname"`
}

type EnrollResponse struct {
	DeviceID string `json:"device_id"`
	Cert     string `json:"cert"`
}

var (
	// No leading dash, slash or URL: package managers would otherwise read the
	// value as an option, or as a local file or remote URL to install.
	pkgRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$`)
	userRe    = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	caNameRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	commandRe = regexp.MustCompile(`^/[A-Za-z0-9._/+-]{1,255}$`)
	modeRe    = regexp.MustCompile(`^0?[0-7]{3}$`)
	// SHA-512 crypt. The alphabet excludes ":" and newlines, so a hash cannot
	// add fields or lines to what chpasswd reads.
	hashRe = regexp.MustCompile(`^\$6\$(rounds=[0-9]{4,9}\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$`)
)

func ValidPackage(s string) bool { return pkgRe.MatchString(s) }

// ValidUser accepts ordinary account names and refuses root, which no task
// may ever target.
func ValidUser(s string) bool { return userRe.MatchString(s) && s != "root" }

// MaxGrant caps how long a single sudo grant can last.
const MaxGrant = 24 * time.Hour

// Validate checks a task payload without touching the system.
func Validate(taskType string, payload json.RawMessage) error {
	switch taskType {
	case TaskPkgInstall, TaskPkgRemove, TaskFlatpakInstall:
		var p PackagesPayload
		if err := strictDecode(payload, &p); err != nil {
			return err
		}
		if len(p.Packages) == 0 {
			return errors.New("no packages given")
		}
		for _, name := range p.Packages {
			if !ValidPackage(name) {
				return fmt.Errorf("invalid package name %q", name)
			}
		}
	case TaskPkgUpgrade:
		return nil
	case TaskFilePut:
		var p FilePutPayload
		if err := strictDecode(payload, &p); err != nil {
			return err
		}
		if !strings.HasPrefix(p.Path, "/") || strings.Contains(p.Path, "..") {
			return fmt.Errorf("invalid path %q", p.Path)
		}
		if p.Mode != "" && !modeRe.MatchString(p.Mode) {
			return fmt.Errorf("invalid mode %q", p.Mode)
		}
	case TaskCAInstall:
		var p CAInstallPayload
		if err := strictDecode(payload, &p); err != nil {
			return err
		}
		if !caNameRe.MatchString(p.Name) {
			return fmt.Errorf("invalid CA name %q", p.Name)
		}
		if !strings.Contains(p.PEM, "BEGIN CERTIFICATE") {
			return errors.New("not a PEM certificate")
		}
	case TaskSudoGrant:
		var p SudoGrantPayload
		if err := strictDecode(payload, &p); err != nil {
			return err
		}
		if !ValidUser(p.User) {
			return fmt.Errorf("invalid user %q", p.User)
		}
		if p.ExpiresAt.IsZero() {
			return errors.New("sudo grant needs an expiry")
		}
		if time.Until(p.ExpiresAt) > MaxGrant {
			return fmt.Errorf("sudo grant longer than %s", MaxGrant)
		}
		for _, c := range p.Commands {
			if !commandRe.MatchString(c) || strings.Contains(c, "..") {
				return fmt.Errorf("invalid command %q", c)
			}
		}
	case TaskSudoRevoke, TaskUserLock, TaskUserUnlock:
		var p UserPayload
		if err := strictDecode(payload, &p); err != nil {
			return err
		}
		if !ValidUser(p.User) {
			return fmt.Errorf("invalid user %q", p.User)
		}
	case TaskUserPassword:
		var p PasswordPayload
		if err := strictDecode(payload, &p); err != nil {
			return err
		}
		if !ValidUser(p.User) {
			return fmt.Errorf("invalid user %q", p.User)
		}
		if !hashRe.MatchString(p.Hash) {
			return errors.New("not a SHA-512 crypt hash")
		}
	case TaskUserCreate:
		var p UserPayload
		if err := strictDecode(payload, &p); err != nil {
			return err
		}
		if !ValidUser(p.User) {
			return fmt.Errorf("invalid user %q", p.User)
		}
		if strings.ContainsAny(p.FullName, ":\n\r") {
			return errors.New("invalid full name")
		}
		for _, g := range p.Groups {
			// Group membership in these equals root, so it must go through
			// the time-limited sudo grant instead.
			if !userRe.MatchString(g) || privilegedGroups[g] {
				return fmt.Errorf("group %q not allowed", g)
			}
		}
	case TaskLimitSet:
		var p LimitPayload
		if err := strictDecode(payload, &p); err != nil {
			return err
		}
		if !ValidUser(p.User) {
			return fmt.Errorf("invalid user %q", p.User)
		}
		if p.CPUPercent < 0 || p.MemoryMB < 0 {
			return errors.New("limits must not be negative")
		}
		if p.CPUPercent == 0 && p.MemoryMB == 0 {
			return errors.New("no limit given")
		}
	default:
		return fmt.Errorf("unknown task type %q", taskType)
	}
	return nil
}

var privilegedGroups = map[string]bool{
	"root": true, "wheel": true, "sudo": true, "adm": true,
	"docker": true, "lxd": true, "libvirt": true, "disk": true, "shadow": true,
}

func strictDecode(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}
	return nil
}
