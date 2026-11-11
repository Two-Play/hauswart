package api

import (
	"strings"
	"time"
)

// TaskLapsed is the output of a task that waited for approval longer than its
// kind allows. Nobody decided on it, so it did not run.
const TaskLapsed = "lapsed: nobody approved it in time"

// RequestLapsed is a request whose task lapsed while it waited.
const RequestLapsed = "lapsed"

// Limits on how long a task waits for approval.
const (
	shortWait = 2 * time.Hour
	longWait  = 7 * 24 * time.Hour
)

// WaitLimit is how long a task of a kind waits for a signature or a passkey.
// What is about the moment, such as a block, more screen time or a restart, is
// likely beside the point after a few hours; the rest waits a week.
func WaitLimit(taskType string) time.Duration {
	if window := ApprovalWindow(taskType); window > 0 {
		return window
	}
	switch taskType {
	case TaskScreenExtend, TaskNotifySend, TaskPowerReboot, TaskPowerShutdown, TaskPowerCancel:
		return shortWait
	}
	if strings.HasPrefix(taskType, "access.") {
		return shortWait
	}
	return longWait
}
