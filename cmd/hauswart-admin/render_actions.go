package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/philippe/hauswart/internal/api"
)

// actionDeadline is the expiry of tasks that carry their own. The signature
// ends with it, so that nobody can hold such a task back and fire it later.
func actionDeadline(taskType string, payload []byte) (time.Time, bool) {
	var p struct {
		ExpiresAt time.Time `json:"expires_at"`
	}
	switch taskType {
	case api.TaskPowerReboot, api.TaskPowerShutdown, api.TaskNotifySend:
		if json.Unmarshal(payload, &p) == nil {
			return p.ExpiresAt, true
		}
	}
	return time.Time{}, false
}

// stillValid refuses to sign what the device would refuse anyway.
func stillValid(expires time.Time) error {
	if !time.Now().Before(expires) {
		return fmt.Errorf("task expired at %s", expires.Format(time.RFC3339))
	}
	return nil
}

func showExpiry(expires time.Time) string {
	return fmt.Sprintf("Only if the device gets it by %s (in %s).",
		expires.Local().Format(time.RFC1123), time.Until(expires).Round(time.Minute))
}

func init() {
	power := func(verb string) func(api.PowerPayload) (string, error) {
		return func(p api.PowerPayload) (string, error) {
			if err := stillValid(p.ExpiresAt); err != nil {
				return "", err
			}
			text := fmt.Sprintf("%s THIS DEVICE in %d minute(s). Unsaved work of everyone on it is lost.", verb, p.DelayMinutes)
			if p.Message != "" {
				text += fmt.Sprintf("\n  Added to the warning: %q", clean(p.Message))
			}
			return text + "\n  " + showExpiry(p.ExpiresAt), nil
		}
	}
	reviewer(api.TaskPowerReboot, power("RESTART"))
	reviewer(api.TaskPowerShutdown, power("SHUT DOWN"))
	reviewer(api.TaskNotifySend, func(p api.NotifyPayload) (string, error) {
		if err := stillValid(p.ExpiresAt); err != nil {
			return "", err
		}
		audience := "everyone logged in to a desktop"
		if p.User != "" {
			audience = "Linux user " + p.User
		}
		return fmt.Sprintf("Show a popup titled \"Hauswart\" to %s:\n%s\n  %s",
			audience, cleanLines(p.Message), showExpiry(p.ExpiresAt)), nil
	})
	reviewer(api.TaskGroupAdd, func(p api.GroupPayload) (string, error) {
		return fmt.Sprintf("ADD Linux user %s to group %s, with all the rights of that group, from the next login", p.User, p.Group), nil
	})
	reviewer(api.TaskGroupRemove, func(p api.GroupPayload) (string, error) {
		return fmt.Sprintf("REMOVE Linux user %s from group %s", p.User, p.Group), nil
	})
}
