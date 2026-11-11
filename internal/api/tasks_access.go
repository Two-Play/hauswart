package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	_ "image/jpeg" // pictures come as PNG or JPEG
	_ "image/png"
	"slices"
	"time"
)

// The access tasks block the screen, refuse logins or cover the screen on a
// device, for everyone with an ordinary account or for some, until it is lifted
// or ends on its own. Each is a type of its own, so that each can be allowed to
// a passkey or not.
const (
	TaskAccessLock  = "access.lock"
	TaskAccessDeny  = "access.deny"
	TaskAccessCover = "access.cover"
	TaskAccessOpen  = "access.open"
)

// AccessTypes are the access tasks, in the order they are offered.
var AccessTypes = []string{TaskAccessLock, TaskAccessDeny, TaskAccessCover, TaskAccessOpen}

// LegacyAccessSet is the one type all access tasks were before. A list of
// types that allows it allows all of them, which is what it meant.
const LegacyAccessSet = "access.set"

// ExpandLegacyTypes replaces access.set in a list of types by what it stood for.
func ExpandLegacyTypes(types []string) []string {
	if !slices.Contains(types, LegacyAccessSet) {
		return types
	}
	out := slices.DeleteFunc(slices.Clone(types), func(t string) bool { return t == LegacyAccessSet })
	for _, t := range AccessTypes {
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// The modes a device keeps for the access tasks. Open lifts what the last one set.
const (
	AccessScreen = "screen"
	AccessLogin  = "login"
	AccessOpen   = "open"
	// AccessFullscreen covers the screen with a notice of its own, which the
	// people at the device cannot close.
	AccessFullscreen = "fullscreen"
)

// MaxAccessImage caps the picture of a full-screen block, so that it stays well
// within a signed task.
const MaxAccessImage = 512 << 10

const maxAccessMessage = 200

// MaxAccessPixels caps the width and the height of the picture.
const MaxAccessPixels = 4096

// MaxAccessBlock caps how long a block may last when it has an end. Without an
// end it lasts until someone lifts it.
const MaxAccessBlock = 30 * 24 * time.Hour

const maxAccessUsers = 50

// AccessBlockPayload is the payload of access.lock and access.deny. No users
// means every ordinary account. A zero Until lasts until access is opened again.
type AccessBlockPayload struct {
	Users []string  `json:"users,omitempty"`
	Until time.Time `json:"until,omitzero"`
}

// AccessCoverPayload is the payload of access.cover: a block that shows one
// line of text and a picture, a PNG or JPEG, base64 encoded.
type AccessCoverPayload struct {
	Users   []string  `json:"users,omitempty"`
	Until   time.Time `json:"until,omitzero"`
	Message string    `json:"message,omitempty"`
	Image   string    `json:"image,omitempty"`
}

// AccessOpenPayload is the payload of access.open, which takes nothing.
type AccessOpenPayload struct{}

// AccessPayload is how a device keeps the block in force, and what every
// access task comes down to.
type AccessPayload struct {
	Mode  string    `json:"mode"`
	Users []string  `json:"users,omitempty"`
	Until time.Time `json:"until,omitzero"`
	// Message and Image are what a full-screen block shows: one line of text, and
	// a PNG or JPEG, base64 encoded.
	Message string `json:"message,omitempty"`
	Image   string `json:"image,omitempty"`
}

// AccessStatus is how a person at the device is blocked, if at all.
type AccessStatus struct {
	Mode  string    `json:"mode"`
	Until time.Time `json:"until,omitzero"`
}

func init() {
	// Every one needs a signature: blocking a device is as much a decision as
	// letting people back in.
	register(TaskAccessLock, false, func(p AccessBlockPayload) error {
		return checkAccess(AccessPayload{Mode: AccessScreen, Users: p.Users, Until: p.Until})
	})
	register(TaskAccessDeny, false, func(p AccessBlockPayload) error {
		return checkAccess(AccessPayload{Mode: AccessLogin, Users: p.Users, Until: p.Until})
	})
	register(TaskAccessCover, false, func(p AccessCoverPayload) error {
		return checkAccess(AccessPayload{Mode: AccessFullscreen, Users: p.Users, Until: p.Until, Message: p.Message, Image: p.Image})
	})
	register(TaskAccessOpen, false, func(AccessOpenPayload) error { return nil })
}

// AccessTask is the task for a block, the reverse of AccessFromTask. Fields
// that the type does not take stay in, so that its check refuses them.
func AccessTask(p AccessPayload) (string, json.RawMessage, error) {
	types := map[string]string{AccessScreen: TaskAccessLock, AccessLogin: TaskAccessDeny,
		AccessFullscreen: TaskAccessCover, AccessOpen: TaskAccessOpen}
	taskType, ok := types[p.Mode]
	if !ok {
		return "", nil, Fail(ErrInvalidAccessMode, p.Mode)
	}
	raw, err := json.Marshal(AccessCoverPayload{Users: p.Users, Until: p.Until, Message: p.Message, Image: p.Image})
	return taskType, raw, err
}

// IsAccessTask says whether a type is one of the access tasks.
func IsAccessTask(taskType string) bool { return slices.Contains(AccessTypes, taskType) }

// AccessFromTask turns an access task into the block a device keeps. The
// payload has to be valid already.
func AccessFromTask(taskType string, raw json.RawMessage) (AccessPayload, error) {
	switch taskType {
	case TaskAccessLock, TaskAccessDeny:
		var p AccessBlockPayload
		if err := strictDecode(raw, &p); err != nil {
			return AccessPayload{}, err
		}
		mode := AccessScreen
		if taskType == TaskAccessDeny {
			mode = AccessLogin
		}
		return AccessPayload{Mode: mode, Users: p.Users, Until: p.Until}, nil
	case TaskAccessCover:
		var p AccessCoverPayload
		if err := strictDecode(raw, &p); err != nil {
			return AccessPayload{}, err
		}
		return AccessPayload{Mode: AccessFullscreen, Users: p.Users, Until: p.Until, Message: p.Message, Image: p.Image}, nil
	case TaskAccessOpen:
		var p AccessOpenPayload
		if err := strictDecode(raw, &p); err != nil {
			return AccessPayload{}, err
		}
		return AccessPayload{Mode: AccessOpen}, nil
	}
	return AccessPayload{}, Fail(ErrUnknownTaskType, taskType)
}

func checkAccess(p AccessPayload) error {
	if p.Mode != AccessScreen && p.Mode != AccessLogin && p.Mode != AccessOpen && p.Mode != AccessFullscreen {
		return Fail(ErrInvalidAccessMode, p.Mode)
	}
	if p.Mode != AccessFullscreen && (p.Message != "" || p.Image != "") {
		return Fail(ErrInvalidAccessMode, p.Mode)
	}
	if !ValidText(p.Message, maxAccessMessage) {
		return Fail(ErrInvalidMessage)
	}
	if p.Image != "" {
		if _, err := AccessImage(p.Image); err != nil {
			return err
		}
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

// AccessImage decodes the picture of a full-screen block and checks that it is a
// PNG or JPEG of at most MaxAccessImage bytes.
func AccessImage(encoded string) ([]byte, error) {
	if len(encoded) > base64.StdEncoding.EncodedLen(MaxAccessImage) {
		return nil, Fail(ErrInvalidAccessImage)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) > MaxAccessImage {
		return nil, Fail(ErrInvalidAccessImage)
	}
	if !bytes.HasPrefix(raw, []byte("\x89PNG\r\n\x1a\n")) && !bytes.HasPrefix(raw, []byte{0xff, 0xd8, 0xff}) {
		return nil, Fail(ErrInvalidAccessImage)
	}
	// A small file can claim a huge picture, which decoding would hold in memory.
	config, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || config.Width < 1 || config.Height < 1 || config.Width > MaxAccessPixels || config.Height > MaxAccessPixels {
		return nil, Fail(ErrInvalidAccessImage)
	}
	return raw, nil
}
