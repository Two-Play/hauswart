package api

import (
	"testing"
	"time"
)

func TestWaitLimitByKind(t *testing.T) {
	for taskType, want := range map[string]time.Duration{
		TaskTerminalOpen: MaxTerminalApproval,
		TaskAccessSet:    2 * time.Hour,
		TaskScreenExtend: 2 * time.Hour,
		TaskPowerReboot:  2 * time.Hour,
		TaskNotifySend:   2 * time.Hour,
		TaskPkgInstall:   7 * 24 * time.Hour,
		TaskUserCreate:   7 * 24 * time.Hour,
	} {
		if got := WaitLimit(taskType); got != want {
			t.Errorf("%s: %v, want %v", taskType, got, want)
		}
	}
}
