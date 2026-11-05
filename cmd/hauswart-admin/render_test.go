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
