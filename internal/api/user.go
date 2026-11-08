package api

import (
	"slices"
	"time"
)

// RequestScreen asks for more screen time today, in minutes.
const RequestScreen = "screen"

const maxRequestText = 200

// requestKinds are what someone can ask for from their desktop.
var requestKinds = []string{RequestSoftware, RequestFlatpak, RequestSudo, RequestScreen}

// UserStatus is what the desktop app of a person learns from the agent, about
// that person only.
type UserStatus struct {
	User       string        `json:"user"`
	ScreenTime *ScreenStatus `json:"screen_time,omitempty"`
	// Shares are the folders in /media that are mounted for this person.
	Shares []string `json:"shares,omitempty"`
	// PolicyIssues says that the device differs from its policy. What differs
	// is for admins.
	PolicyIssues bool           `json:"policy_issues,omitempty"`
	Nextcloud    *NextcloudRule `json:"nextcloud,omitempty"`
	// Suspended says that Hauswart holds the device back: no requests for now.
	Suspended bool `json:"suspended,omitempty"`
	// Access says that this person may not use the device right now.
	Access *AccessStatus `json:"access,omitempty"`
	// Terminal says that an admin works on the device in a live shell.
	Terminal  *TerminalStatus `json:"terminal,omitempty"`
	Dashboard string          `json:"dashboard"`
}

// TerminalStatus is a live shell on the device, for the people at it.
type TerminalStatus struct {
	User     string    `json:"user"`
	Approver string    `json:"approver"`
	Since    time.Time `json:"since"`
	Until    time.Time `json:"until"`
}

// ScreenStatus is how someone stands with their screen time.
type ScreenStatus struct {
	Allowed bool      `json:"allowed"`
	Until   time.Time `json:"until,omitzero"`
}

// UserRequest is what someone asks for on their desktop.
type UserRequest struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
	Reason string `json:"reason,omitempty"`
}

// The status of a request just filed.
const (
	RequestOpen     = "open"
	RequestApproved = "approved"
)

// The further states of a request, as a device learns them from the server.
const (
	RequestDenied  = "denied"
	RequestSigning = "signing"
	RequestRunning = "running"
	RequestDone    = "done"
	RequestFailed  = "failed"
)

// RequestState is a request filed on a device, for the person who filed it.
// The reason stays on the server: whoever runs the device may read this.
type RequestState struct {
	ID        string `json:"id"`
	User      string `json:"user"`
	Kind      string `json:"kind"`
	Detail    string `json:"detail"`
	State     string `json:"state"`
	CreatedAt int64  `json:"created_at"`
}

// What happened on a device, as the desktop app names it.
const (
	EventSudoGranted       = "sudo.granted"
	EventSudoRevoked       = "sudo.revoked"
	EventSudoExpiring      = "sudo.expiring"
	EventSudoExpired       = "sudo.expired"
	EventSoftwareInstalled = "software.installed"
	EventSoftwareRemoved   = "software.removed"
	EventSoftwareUpgraded  = "software.upgraded"
	EventSoftwareFailed    = "software.failed"
	EventFlatpakArrived    = "software.flatpak_arrived"
	EventUpdateFailed      = "software.update_failed"
	EventAccountLocked     = "account.locked"
	EventAccountUnlocked   = "account.unlocked"
	EventAccountPassword   = "account.password"
	EventGroupAdded        = "account.group_added"
	EventGroupRemoved      = "account.group_removed"
	EventPolicyChanged     = "policy.changed"
	EventPolicyCleared     = "policy.cleared"
	EventDeviceSuspended   = "device.suspended"
	EventDeviceResumed     = "device.resumed"
	EventAccessScreen      = "access.screen"
	EventAccessLogin       = "access.login"
	EventAccessEnding      = "access.ending"
	EventAccessOpen        = "access.open"
	EventTerminalStarted   = "terminal.started"
	EventTerminalEnded     = "terminal.ended"
)

// DeviceEvent is a change Hauswart made that people at the device should know.
type DeviceEvent struct {
	Kind string `json:"kind"`
	// User is the person it is about. Empty means the whole device.
	User   string    `json:"user,omitempty"`
	Detail string    `json:"detail,omitempty"`
	Until  time.Time `json:"until,omitzero"`
	At     time.Time `json:"at"`
}

// History is what the desktop app shows someone: their requests, and what
// changed for them or for the whole device. Newest first.
type History struct {
	Requests []RequestState `json:"requests"`
	Events   []DeviceEvent  `json:"events"`
}

// RequestAnswer is what filing a request returns.
type RequestAnswer struct {
	ID     string `json:"id,omitempty"`
	Status string `json:"status"`
}

// Normalized reads a missing or unknown status as open: someone still decides.
func (a RequestAnswer) Normalized() string {
	if a.Status == RequestApproved {
		return RequestApproved
	}
	return RequestOpen
}

// DeviceRequest is a UserRequest on its way to the server, with who filed it.
type DeviceRequest struct {
	User string `json:"user"`
	UserRequest
}

// CheckUserRequest refuses what is no request. The agent reads this from anyone
// on the device, and the server from any device.
func CheckUserRequest(r UserRequest) error {
	if !slices.Contains(requestKinds, r.Kind) {
		return Fail(ErrUnknownRequestKind, r.Kind)
	}
	if r.Detail == "" || !ValidText(r.Detail, maxRequestText) || !ValidText(r.Reason, maxRequestText) {
		return Fail(ErrInvalidRequest)
	}
	return nil
}
