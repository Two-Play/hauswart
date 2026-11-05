package main

import (
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/philippe/hauswart/internal/api"
)

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReviewShowsFullRoot(t *testing.T) {
	text, _, err := review(api.TaskSudoGrant, mustJSON(t, api.SudoGrantPayload{User: "anna", ExpiresAt: time.Now().Add(time.Hour)}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "FULL ROOT") {
		t.Fatalf("got %q", text)
	}
}

func TestReviewRefusesExpiredGrant(t *testing.T) {
	if _, _, err := review(api.TaskSudoGrant, mustJSON(t, api.SudoGrantPayload{User: "anna", ExpiresAt: time.Now().Add(-time.Minute)})); err == nil {
		t.Fatal("offered an expired grant")
	}
}

func TestReviewRefusesTypesTheServerMustNotOffer(t *testing.T) {
	hash := "$6$salt$" + strings.Repeat("a", 86)
	if _, _, err := review(api.TaskUserPassword, mustJSON(t, api.PasswordPayload{User: "anna", Hash: hash})); err == nil {
		t.Error("would sign a password hash from the server")
	}
	if _, _, err := review(api.TaskKeysSet, json.RawMessage(`{"keys":["x"]}`)); err == nil {
		t.Error("would sign keys from the server")
	}
	if _, _, err := review("shell.exec", json.RawMessage(`{}`)); err == nil {
		t.Error("would sign an unknown type")
	}
}

// Whatever the server adds must not end up under the signature.
func TestReviewSignsItsOwnEncoding(t *testing.T) {
	raw := json.RawMessage(`{"packages":["vim"],"hidden":"x"}`)
	if _, _, err := review(api.TaskPkgInstall, raw); err == nil {
		t.Fatal("accepted a payload with an unknown field")
	}
	_, payload, err := review(api.TaskPkgInstall, json.RawMessage(`  {"packages": ["vim"]}  `))
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != `{"packages":["vim"]}` {
		t.Fatalf("got %s", payload)
	}
}

func TestReviewStripsTerminalEscapes(t *testing.T) {
	content := "ok\x1b[2K\x1b[1Ahidden"
	text, _, err := review(api.TaskFilePut, mustJSON(t, api.FilePutPayload{Path: "/etc/hauswart.d/a", Content: content}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(text, 0x1b) {
		t.Fatalf("escape reached the terminal: %q", text)
	}
}

func TestReviewShowsCertificateFingerprint(t *testing.T) {
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("data")})
	text, _, err := review(api.TaskCAInstall, mustJSON(t, api.CAInstallPayload{Name: "a", PEM: string(cert)}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7") {
		t.Fatalf("got %q", text)
	}
}

func TestReviewSpellsOutPowerActions(t *testing.T) {
	soon := time.Now().Add(time.Hour)
	text, signed, err := review(api.TaskPowerReboot, mustJSON(t, api.PowerPayload{DelayMinutes: 7, Message: "Kernel", ExpiresAt: soon}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"RESTART THIS DEVICE", "7 minute(s)", "Kernel", "gets it by"} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in %q", want, text)
		}
	}
	until, ok := actionDeadline(api.TaskPowerReboot, signed)
	if !ok || !until.Equal(soon) {
		t.Fatalf("signature does not end with the task: %v", until)
	}
	if !signedUntil(api.TaskPowerReboot, signed).Equal(soon) {
		t.Fatal("signature outlives the task")
	}
	if text, _, _ := review(api.TaskPowerShutdown, mustJSON(t, api.PowerPayload{DelayMinutes: 7, ExpiresAt: soon})); !strings.Contains(text, "SHUT DOWN THIS DEVICE") {
		t.Fatalf("got %q", text)
	}
}

func TestReviewRefusesExpiredActions(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	if _, _, err := review(api.TaskPowerReboot, mustJSON(t, api.PowerPayload{DelayMinutes: 1, ExpiresAt: past})); err == nil {
		t.Fatal("offered an expired reboot")
	}
	if _, _, err := review(api.TaskNotifySend, mustJSON(t, api.NotifyPayload{Message: "x", ExpiresAt: past})); err == nil {
		t.Fatal("offered an expired message")
	}
}

func TestReviewShowsTheMessageAndItsAudience(t *testing.T) {
	soon := time.Now().Add(time.Hour)
	text, _, err := review(api.TaskNotifySend, mustJSON(t, api.NotifyPayload{Message: "Essen!", ExpiresAt: soon}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, `titled "Hauswart"`) || !strings.Contains(text, "everyone") || !strings.Contains(text, "Essen!") {
		t.Fatalf("got %q", text)
	}
	text, _, _ = review(api.TaskNotifySend, mustJSON(t, api.NotifyPayload{Message: "Essen!", User: "anna", ExpiresAt: soon}))
	if !strings.Contains(text, "user anna") {
		t.Fatalf("got %q", text)
	}
}

func TestReviewOfGroups(t *testing.T) {
	text, _, err := review(api.TaskGroupAdd, mustJSON(t, api.GroupPayload{User: "anna", Group: "video"}))
	if err != nil || !strings.Contains(text, "ADD Linux user anna to group video") {
		t.Fatalf("%q, %v", text, err)
	}
	text, _, err = review(api.TaskGroupRemove, mustJSON(t, api.GroupPayload{User: "anna", Group: "video"}))
	if err != nil || !strings.Contains(text, "REMOVE Linux user anna from group video") {
		t.Fatalf("%q, %v", text, err)
	}
	if _, _, err := review(api.TaskGroupAdd, mustJSON(t, api.GroupPayload{User: "anna", Group: "wheel"})); err == nil {
		t.Fatal("offered wheel")
	}
}

func TestCancelIsNotOffered(t *testing.T) {
	if _, _, err := review(api.TaskPowerCancel, json.RawMessage(`{}`)); err == nil {
		t.Fatal("a task without a signature ended up in the signing queue")
	}
}
