package api

import "slices"

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
}

// PasskeyEligible says whether a type can be approved with a passkey at all.
func PasskeyEligible(taskType string) bool {
	return slices.Contains(DefaultPasskeyTypes, taskType)
}
