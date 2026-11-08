package admintool

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Two-Play/hauswart/internal/api"
)

func TestPasskeyTypesReviewSaysWhatChanges(t *testing.T) {
	raw, _ := json.Marshal(api.PasskeyTypesPayload{Types: []string{api.TaskTerminalOpen, api.TaskPkgInstall}})
	text, payload, err := review(api.TaskPasskeyTypes, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "+ open a live ROOT SHELL") || !strings.Contains(text, "- remove packages") {
		t.Fatalf("text: %s", text)
	}
	changes := passkeyTypeChanges(&api.Report{PasskeyTypes: []string{api.TaskPkgInstall, "power.reboot"}}, payload)
	if !strings.Contains(changes, "NEW BY PASSKEY: open a live ROOT SHELL") || !strings.Contains(changes, "no longer by passkey: restart") {
		t.Fatalf("changes: %s", changes)
	}
	if policyFingerprint(api.TaskPasskeyTypes, payload) == "" {
		t.Fatal("identical lists for several devices are not grouped")
	}
}
