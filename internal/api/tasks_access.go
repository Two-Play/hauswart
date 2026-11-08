package api

import (
	"bytes"
	"encoding/base64"
	"image"
	_ "image/jpeg" // pictures come as PNG or JPEG
	_ "image/png"
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

// AccessPayload says who may not use a device and how. No users means every
// ordinary account. A zero Until lasts until access is opened again.
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
	// Every mode needs a signature: blocking a device is as much a decision as
	// letting people back in.
	register(TaskAccessSet, false, checkAccess)
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
