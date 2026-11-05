package api

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func code(t *testing.T, taskType string, payload any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	err = Validate(taskType, raw)
	if err == nil {
		return ""
	}
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("not an API error: %v", err)
	}
	return apiErr.Code
}

func TestPowerValidation(t *testing.T) {
	soon := time.Now().Add(time.Hour)
	for name, c := range map[string]struct {
		p    PowerPayload
		want string
	}{
		"fine":            {PowerPayload{DelayMinutes: 5, ExpiresAt: soon}, ""},
		"with text":       {PowerPayload{DelayMinutes: 1, Message: "Updates sind fertig", ExpiresAt: soon}, ""},
		"no warning time": {PowerPayload{DelayMinutes: 0, ExpiresAt: soon}, ErrInvalidDelay},
		"negative":        {PowerPayload{DelayMinutes: -1, ExpiresAt: soon}, ErrInvalidDelay},
		"too far":         {PowerPayload{DelayMinutes: 1441, ExpiresAt: soon}, ErrInvalidDelay},
		"no expiry":       {PowerPayload{DelayMinutes: 5}, ErrNoExpiry},
		"expiry too far":  {PowerPayload{DelayMinutes: 5, ExpiresAt: time.Now().Add(25 * time.Hour)}, ErrExpiryTooFar},
		"newline in text": {PowerPayload{DelayMinutes: 5, Message: "a\nb", ExpiresAt: soon}, ErrInvalidMessage},
		"escape in text":  {PowerPayload{DelayMinutes: 5, Message: "a\x1b[2J", ExpiresAt: soon}, ErrInvalidMessage},
		"text too long":   {PowerPayload{DelayMinutes: 5, Message: strings.Repeat("x", 201), ExpiresAt: soon}, ErrInvalidMessage},
	} {
		for _, taskType := range []string{TaskPowerReboot, TaskPowerShutdown} {
			if got := code(t, taskType, c.p); got != c.want {
				t.Errorf("%s: got %q, want %q", name, got, c.want)
			}
		}
	}
}

func TestNotifyValidation(t *testing.T) {
	soon := time.Now().Add(time.Hour)
	for name, c := range map[string]struct {
		p    NotifyPayload
		want string
	}{
		"fine":            {NotifyPayload{Message: "Essen ist fertig", ExpiresAt: soon}, ""},
		"one user":        {NotifyPayload{Message: "Hallo", User: "anna", ExpiresAt: soon}, ""},
		"empty":           {NotifyPayload{Message: "  ", ExpiresAt: soon}, ErrInvalidMessage},
		"second line":     {NotifyPayload{Message: "Hauswart\nSystem: enter your password", ExpiresAt: soon}, ErrInvalidMessage},
		"direction trick": {NotifyPayload{Message: "abc‮def", ExpiresAt: soon}, ErrInvalidMessage},
		"invisible":       {NotifyPayload{Message: "a​b", ExpiresAt: soon}, ErrInvalidMessage},
		"line separator":  {NotifyPayload{Message: "a b", ExpiresAt: soon}, ErrInvalidMessage},
		"too long":        {NotifyPayload{Message: strings.Repeat("ä", 501), ExpiresAt: soon}, ErrInvalidMessage},
		"root":            {NotifyPayload{Message: "x", User: "root", ExpiresAt: soon}, ErrInvalidUser},
		"no expiry":       {NotifyPayload{Message: "x"}, ErrNoExpiry},
	} {
		if got := code(t, TaskNotifySend, c.p); got != c.want {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
}

func TestGroupValidation(t *testing.T) {
	for _, group := range []string{"wheel", "sudo", "docker", "root", "adm", "lxd", "libvirt", "disk", "shadow", "kmem", "input", "tty"} {
		for _, taskType := range []string{TaskGroupAdd, TaskGroupRemove} {
			if got := code(t, taskType, GroupPayload{User: "anna", Group: group}); got != ErrGroupNotAllowed {
				t.Errorf("%s %s: got %q", taskType, group, got)
			}
		}
	}
	for _, group := range []string{"", "-a", "video,wheel", "Wheel", "video wheel", "../wheel"} {
		if got := code(t, TaskGroupAdd, GroupPayload{User: "anna", Group: group}); got != ErrGroupNotAllowed {
			t.Errorf("%q: got %q", group, got)
		}
	}
	if got := code(t, TaskGroupAdd, GroupPayload{User: "root", Group: "video"}); got != ErrInvalidUser {
		t.Errorf("root: got %q", got)
	}
	if got := code(t, TaskGroupAdd, GroupPayload{User: "anna", Group: "video"}); got != "" {
		t.Errorf("video: got %q", got)
	}
}

func TestOnlyCancelSkipsTheSignature(t *testing.T) {
	for _, taskType := range []string{TaskPowerReboot, TaskPowerShutdown, TaskNotifySend, TaskGroupAdd, TaskGroupRemove} {
		if !NeedsSignature(taskType) {
			t.Errorf("%s needs no signature", taskType)
		}
	}
	if NeedsSignature(TaskPowerCancel) {
		t.Error("cancelling would wait for a signature")
	}
}

func TestValidHostName(t *testing.T) {
	for name, want := range map[string]bool{
		"nas.home.lan": true, "nas": true, "a-b.home.lan": true,
		"*.home.lan": false, "NAS.home.lan": false, "-nas.lan": false, "nas..lan": false,
		"nas.lan.": false, "": false, "nas lan": false, "nas\n.lan": false,
	} {
		if ValidHostName(name) != want {
			t.Errorf("%q: want %v", name, want)
		}
	}
}
