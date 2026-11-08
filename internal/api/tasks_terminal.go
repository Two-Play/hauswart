package api

import (
	"encoding/base64"
	"maps"
	"time"
)

// TaskTerminalOpen opens a live shell on a device, which the device connects
// to the server for. One task is one session.
const TaskTerminalOpen = "terminal.open"

// TerminalRoot is the user of a shell as root.
const TerminalRoot = "root"

const (
	// MaxTerminalMinutes caps how long a session lasts.
	MaxTerminalMinutes = 240
	// DefaultTerminalMinutes is what a session lasts unless asked otherwise.
	DefaultTerminalMinutes = 60
	// MaxTerminalApproval caps how long an approved session may wait to start.
	// The approval is for now, not for a session someone opens next week.
	MaxTerminalApproval = 15 * time.Minute
	// TerminalSessionBytes is the length of a session ID before encoding.
	TerminalSessionBytes = 32
)

// Error codes of the live terminal.
const (
	ErrInvalidTerminal     = "invalid_terminal"
	ErrTerminalUnprotected = "terminal_unprotected"
	ErrTerminalGone        = "terminal_gone"
	ErrTerminalApproval    = "terminal_approval_too_long"
)

// TerminalPayload says who the shell runs as and for how long. Session ties the
// connection of the device to the task: the server made it, the device returns it.
type TerminalPayload struct {
	Session string `json:"session"`
	User    string `json:"user"`
	Minutes int    `json:"minutes"`
}

func init() {
	register(TaskTerminalOpen, false, checkTerminal)
	maps.Copy(Messages, map[string]string{
		ErrInvalidTerminal:     "invalid terminal session %s",
		ErrTerminalUnprotected: "a live terminal needs a protected device",
		ErrTerminalGone:        "the terminal session has ended or never started",
		ErrTerminalApproval:    "an approved terminal session must start within %s",
	})
}

// ValidTerminalSession accepts what NewTerminalSession makes.
func ValidTerminalSession(s string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(raw) == TerminalSessionBytes && base64.RawURLEncoding.EncodeToString(raw) == s
}

func checkTerminal(p TerminalPayload) error {
	if !ValidTerminalSession(p.Session) {
		return Fail(ErrInvalidTerminal, "session")
	}
	if p.User != TerminalRoot && !ValidUser(p.User) {
		return Fail(ErrInvalidUser, p.User)
	}
	if p.Minutes < 1 || p.Minutes > MaxTerminalMinutes {
		return Fail(ErrInvalidTerminal, "minutes")
	}
	return nil
}

// ApprovalWindow is how far ahead the approval of a task may reach, zero for
// no limit beyond the usual ones. The device checks it for signatures and
// passkeys alike.
func ApprovalWindow(taskType string) time.Duration {
	if taskType == TaskTerminalOpen {
		return MaxTerminalApproval
	}
	return 0
}
