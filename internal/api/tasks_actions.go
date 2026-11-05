package api

import (
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Task types for actions on a device that an admin decides one by one.
const (
	TaskPowerReboot   = "power.reboot"
	TaskPowerShutdown = "power.shutdown"
	TaskPowerCancel   = "power.cancel"
	TaskNotifySend    = "notify.send"
	TaskGroupAdd      = "group.add"
	TaskGroupRemove   = "group.remove"
)

const (
	// MaxPowerDelay caps how far ahead a reboot or shutdown can be scheduled.
	MaxPowerDelay = 24 * time.Hour
	// MaxActionWindow caps how long a power task or message stays valid. It is
	// short on purpose: whoever holds such a task back, a compromised server
	// or a device that is switched off, must not be able to fire it at a
	// moment nobody expects.
	MaxActionWindow = 24 * time.Hour

	maxPowerMessage  = 200
	maxNotifyMessage = 500
)

// PowerPayload schedules a reboot or shutdown. The delay is at least a minute,
// so that people get a warning and the agent can report before it goes down.
type PowerPayload struct {
	DelayMinutes int       `json:"delay_minutes"`
	Message      string    `json:"message,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// NotifyPayload shows a popup in running desktop sessions, of one user or, if
// User is empty, of everyone logged in.
type NotifyPayload struct {
	Message   string    `json:"message"`
	User      string    `json:"user,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GroupPayload adds a Linux user to a group or removes them from it.
type GroupPayload struct {
	User  string `json:"user"`
	Group string `json:"group"`
}

func init() {
	register(TaskPowerReboot, false, checkPower)
	register(TaskPowerShutdown, false, checkPower)
	// Cancelling only stops what was scheduled, so it must not wait for a
	// signature while the minutes run out.
	register(TaskPowerCancel, true, func(struct{}) error { return nil })
	register(TaskNotifySend, false, checkNotify)
	register(TaskGroupAdd, false, checkGroup)
	register(TaskGroupRemove, false, checkGroup)
}

func checkPower(p PowerPayload) error {
	if limit := int(MaxPowerDelay / time.Minute); p.DelayMinutes < 1 || p.DelayMinutes > limit {
		return Fail(ErrInvalidDelay, strconv.Itoa(limit))
	}
	if !ValidText(p.Message, maxPowerMessage) {
		return Fail(ErrInvalidMessage)
	}
	return checkWindow(p.ExpiresAt)
}

func checkNotify(p NotifyPayload) error {
	if strings.TrimSpace(p.Message) == "" || !ValidText(p.Message, maxNotifyMessage) {
		return Fail(ErrInvalidMessage)
	}
	if p.User != "" && !ValidUser(p.User) {
		return Fail(ErrInvalidUser, p.User)
	}
	return checkWindow(p.ExpiresAt)
}

func checkWindow(expires time.Time) error {
	if expires.IsZero() {
		return Fail(ErrNoExpiry)
	}
	if time.Until(expires) > MaxActionWindow {
		return Fail(ErrExpiryTooFar, MaxActionWindow.String())
	}
	return nil
}

func checkGroup(p GroupPayload) error {
	if !ValidUser(p.User) {
		return Fail(ErrInvalidUser, p.User)
	}
	// Membership in these equals root, so it must go through the time-limited
	// sudo grant instead. Removal is refused too, because taking an admin out
	// of wheel can lock everyone out of a device.
	if !userRe.MatchString(p.Group) || privilegedGroups[p.Group] {
		return Fail(ErrGroupNotAllowed, p.Group)
	}
	return nil
}

// ValidText accepts one line for a person to read. Besides control characters,
// it refuses invisible format characters such as right-to-left overrides, which
// could make a message look different to the admin who signs it.
func ValidText(s string, maxRunes int) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > maxRunes {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
	}) < 0
}

var hostNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// ValidHostName accepts a lower case DNS name. Wildcards are not part of it: a
// certificate for one name cannot be misused for its neighbours.
func ValidHostName(s string) bool { return len(s) <= 253 && hostNameRe.MatchString(s) }
