package api

import (
	"encoding/json"
	"slices"
	"time"
)

// PasskeyCapable is the ceiling of what a passkey can ever approve. Any type
// missing here stays with the signing tool, including every type added later,
// until someone decides otherwise here: sudo, keys, files, CAs and passwords
// never come within reach of a page the server delivers.
var PasskeyCapable = []string{
	TaskPkgInstall,
	TaskPkgRemove,
	TaskPkgUpgrade,
	TaskFlatpakInstall,
	"power.reboot",
	"power.shutdown",
	"power.cancel",
	"notify.send",
	// At most a few hours of today, and an approver has to be able to give them
	// from a phone.
	TaskScreenExtend,
	// Blocking or opening access, but a block approved by passkey must end
	// within a day: see PasskeyLimits.
	TaskAccessLock,
	TaskAccessDeny,
	TaskAccessCover,
	TaskAccessOpen,
	// A live shell, one session per touch, which must start within minutes:
	// see ApprovalWindow.
	TaskTerminalOpen,
}

// DefaultPasskeyTypes is what a new device lets a passkey approve, until a
// signed passkeys.types says otherwise.
var DefaultPasskeyTypes = slices.Clone(PasskeyCapable)

// PasskeyEligible says whether a type can be approved with a passkey at all.
func PasskeyEligible(taskType string) bool {
	return slices.Contains(PasskeyCapable, taskType)
}

// MaxPasskeyBlock caps a block that a passkey approves. One touch on a page
// a hacked server delivers must not lock everyone out for good.
const MaxPasskeyBlock = 24 * time.Hour

// PasskeyLimits checks what a passkey may approve beyond its type. The device
// runs it on the approved payload.
func PasskeyLimits(taskType string, payload json.RawMessage, now time.Time) error {
	if !IsAccessTask(taskType) || taskType == TaskAccessOpen {
		return nil
	}
	p, err := AccessFromTask(taskType, payload)
	if err != nil {
		return err
	}
	if p.Until.IsZero() || p.Until.Sub(now) > MaxPasskeyBlock {
		return Fail(ErrPasskeyBlockTooLong, MaxPasskeyBlock.String())
	}
	return nil
}
