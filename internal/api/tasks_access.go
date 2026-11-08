package api

import (
	"slices"
	"time"
)

// TaskAccessSet blocks the screen or refuses logins on a device, for everyone
// with an ordinary account or for some, until it is lifted or ends on its own.
const TaskAccessSet = "access.set"

// The modes of access.set. Open lifts what the last one set.
const (
	AccessScreen = "screen"
	AccessLogin  = "login"
	AccessOpen   = "open"
)

// MaxAccessBlock caps how long a block may last when it has an end. Without an
// end it lasts until someone lifts it.
const MaxAccessBlock = 30 * 24 * time.Hour

const maxAccessUsers = 50

// AccessPayload says who may not use a device and how. No users means every
// ordinary account. A zero Until lasts until access is opened again.
type AccessPayload struct {
	Mode  string    `json:"mode"`
	Users []string  `json:"users,omitempty"`
	Until time.Time `json:"until,omitzero"`
}

// AccessStatus is how a person at the device is blocked, if at all.
type AccessStatus struct {
	Mode  string    `json:"mode"`
	Until time.Time `json:"until,omitzero"`
}

func init() {
	// Every mode needs a signature: blocking a device is as much a decision as
	// letting people back in.
	register(TaskAccessSet, false, checkAccess)
}

func checkAccess(p AccessPayload) error {
	if p.Mode != AccessScreen && p.Mode != AccessLogin && p.Mode != AccessOpen {
		return Fail(ErrInvalidAccessMode, p.Mode)
	}
	if p.Mode == AccessOpen && (len(p.Users) > 0 || !p.Until.IsZero()) {
		return Fail(ErrInvalidAccessMode, p.Mode)
	}
	if len(p.Users) > maxAccessUsers {
		return Fail(ErrInvalidUser, "too many")
	}
	for i, user := range p.Users {
		if !ValidUser(user) || slices.Contains(p.Users[:i], user) {
			return Fail(ErrInvalidUser, user)
		}
	}
	if !p.Until.IsZero() {
		if !time.Now().Before(p.Until) {
			return Fail(ErrAccessEnded)
		}
		if time.Until(p.Until) > MaxAccessBlock {
			return Fail(ErrExpiryTooFar, MaxAccessBlock.String())
		}
	}
	return nil
}
