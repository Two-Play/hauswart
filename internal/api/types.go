// Package api holds the wire types shared by server and agent, plus the
// validation rules for every task. Both sides validate: the server to give
// early feedback, the agent because it is the actual enforcement boundary.
package api

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"regexp"
	"strings"
	"time"
	"unicode"
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

type RenewRequest struct {
	CSR string `json:"csr"`
}

type RenewResponse struct {
	Cert string `json:"cert"`
}

type EnrollResponse struct {
	DeviceID string `json:"device_id"`
	Cert     string `json:"cert"`
}

var (
	// No leading dash, slash or URL: package managers would otherwise read the
	// value as an option, or as a local file or remote URL to install.
	// A trailing "-" would make apt remove the package instead. A trailing "+"
	// only means "install" and is part of real names such as g++.
	pkgRe     = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._+:-]{0,126}[A-Za-z0-9._+:])?$`)
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
			return Fail(ErrNoPackages)
		}
		for _, name := range p.Packages {
			if !ValidPackage(name) {
				return Fail(ErrInvalidPackage, name)
			}
		}
	case TaskPkgUpgrade:
		return nil
	case TaskFilePut:
		var p FilePutPayload
		if err := strictDecode(payload, &p); err != nil {
			return err
		}
		if !strings.HasPrefix(p.Path, "/") || strings.Contains(p.Path, "..") || hasControl(p.Path) {
			return Fail(ErrInvalidPath, p.Path)
		}
		if p.Mode != "" && !modeRe.MatchString(p.Mode) {
			return Fail(ErrInvalidMode, p.Mode)
		}
	case TaskCAInstall:
		var p CAInstallPayload
		if err := strictDecode(payload, &p); err != nil {
			return err
		}
		if !caNameRe.MatchString(p.Name) {
			return Fail(ErrInvalidCAName, p.Name)
		}
		if !singleCertificate(p.PEM) {
			return Fail(ErrNotPEM)
		}
	case TaskSudoGrant:
		var p SudoGrantPayload
		if err := strictDecode(payload, &p); err != nil {
			return err
		}
		if !ValidUser(p.User) {
			return Fail(ErrInvalidUser, p.User)
		}
		if p.ExpiresAt.IsZero() {
			return Fail(ErrSudoNoExpiry)
		}
		if time.Until(p.ExpiresAt) > MaxGrant {
			return Fail(ErrSudoTooLong, MaxGrant.String())
		}
		for _, c := range p.Commands {
			if !commandRe.MatchString(c) || strings.Contains(c, "..") {
				return Fail(ErrInvalidCommand, c)
			}
		}
	case TaskSudoRevoke, TaskUserLock, TaskUserUnlock:
		var p UserPayload
		if err := strictDecode(payload, &p); err != nil {
			return err
		}
		if !ValidUser(p.User) {
			return Fail(ErrInvalidUser, p.User)
		}
	case TaskUserPassword:
		var p PasswordPayload
		if err := strictDecode(payload, &p); err != nil {
			return err
		}
		if !ValidUser(p.User) {
			return Fail(ErrInvalidUser, p.User)
		}
		if !hashRe.MatchString(p.Hash) {
			return Fail(ErrInvalidHash)
		}
	case TaskUserCreate:
		var p UserPayload
		if err := strictDecode(payload, &p); err != nil {
			return err
		}
		if !ValidUser(p.User) {
			return Fail(ErrInvalidUser, p.User)
		}
		if strings.Contains(p.FullName, ":") || hasControl(p.FullName) {
			return Fail(ErrInvalidFullName)
		}
		for _, g := range p.Groups {
			// Group membership in these equals root, so it must go through
			// the time-limited sudo grant instead.
			if !userRe.MatchString(g) || privilegedGroups[g] {
				return Fail(ErrGroupNotAllowed, g)
			}
		}
	case TaskLimitSet:
		var p LimitPayload
		if err := strictDecode(payload, &p); err != nil {
			return err
		}
		if !ValidUser(p.User) {
			return Fail(ErrInvalidUser, p.User)
		}
		if p.CPUPercent < 0 || p.MemoryMB < 0 {
			return Fail(ErrNegativeLimit)
		}
		if p.CPUPercent == 0 && p.MemoryMB == 0 {
			return Fail(ErrNoLimit)
		}
	default:
		return Fail(ErrUnknownTaskType, taskType)
	}
	return nil
}

func hasControl(s string) bool { return strings.IndexFunc(s, unicode.IsControl) >= 0 }

// singleCertificate accepts exactly one PEM certificate. A second block would
// otherwise go into the trust store unnoticed, because whoever reviews a task
// sees only the first.
func singleCertificate(s string) bool {
	block, rest := pem.Decode([]byte(s))
	return block != nil && block.Type == "CERTIFICATE" && len(bytes.TrimSpace(rest)) == 0
}

var privilegedGroups = map[string]bool{
	"root": true, "wheel": true, "sudo": true, "adm": true,
	"docker": true, "lxd": true, "libvirt": true, "disk": true, "shadow": true,
}

func strictDecode(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return Fail(ErrInvalidPayload, err.Error())
	}
	return nil
}
