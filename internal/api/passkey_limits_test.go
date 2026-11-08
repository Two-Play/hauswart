package api

import (
	"encoding/json"
	"testing"
	"time"
)

func TestPasskeyBlocksEndWithinADay(t *testing.T) {
	now := time.Now()
	for name, c := range map[string]struct {
		p  AccessPayload
		ok bool
	}{
		"open":              {AccessPayload{Mode: AccessOpen}, true},
		"a few hours":       {AccessPayload{Mode: AccessLogin, Until: now.Add(3 * time.Hour)}, true},
		"without an end":    {AccessPayload{Mode: AccessLogin}, false},
		"longer than a day": {AccessPayload{Mode: AccessFullscreen, Until: now.Add(25 * time.Hour)}, false},
	} {
		raw, _ := json.Marshal(c.p)
		if err := PasskeyLimits(TaskAccessSet, raw, now); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, gone := range []string{"group.add", "group.remove", TaskUserLock, TaskUserUnlock} {
		if PasskeyEligible(gone) {
			t.Errorf("%s is still within reach of a passkey", gone)
		}
	}
}
