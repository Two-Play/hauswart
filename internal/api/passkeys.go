package api

import (
	"encoding/json"
	"slices"
	"time"
)

// DefaultPasskeyTypes is both the default of a device's own list and the ceiling
// of what a passkey can ever approve. Any type missing here stays with the signing
// tool, including every type added later, until someone decides otherwise here.
// A list on a device can narrow this, never widen it.
var DefaultPasskeyTypes = []string{
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
	TaskAccessSet,
}

// PasskeyEligible says whether a type can be approved with a passkey at all.
func PasskeyEligible(taskType string) bool {
	return slices.Contains(DefaultPasskeyTypes, taskType)
}

// MaxPasskeyBlock caps a block that a passkey approves. One touch on a page
// a hacked server delivers must not lock everyone out for good.
const MaxPasskeyBlock = 24 * time.Hour

// PasskeyLimits checks what a passkey may approve beyond its type. The device
// runs it on the approved payload.
func PasskeyLimits(taskType string, payload json.RawMessage, now time.Time) error {
	if taskType != TaskAccessSet {
		return nil
	}
	var p AccessPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return err
	}
	if p.Mode == AccessOpen {
		return nil
	}
	if p.Until.IsZero() || p.Until.Sub(now) > MaxPasskeyBlock {
		return Fail(ErrPasskeyBlockTooLong, MaxPasskeyBlock.String())
	}
	return nil
}
