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
	Dashboard    string         `json:"dashboard"`
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
