package admintool

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Two-Play/hauswart/internal/api"
)

// An older tool meets a field or a task type it does not know, and says what
// to do about it.
func TestOlderToolSaysToUpdate(t *testing.T) {
	_, _, err := review(api.TaskPkgInstall, json.RawMessage(`{"packages":["vim"],"daily_minutes":30}`))
	if err == nil || !strings.Contains(err.Error(), "daily_minutes") || !strings.Contains(err.Error(), "update hauswart-admin") {
		t.Fatalf("unknown field: %v", err)
	}
	_, _, err = review("teleport.now", json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "update hauswart-admin") {
		t.Fatalf("unknown type: %v", err)
	}
}

func TestOutdatedComparesTheSchema(t *testing.T) {
	s := &Session{schema: func() (string, error) { return api.Schema(), nil }}
	if got := s.Outdated(); got != "" {
		t.Fatalf("same schema: %q", got)
	}
	s.schema = func() (string, error) { return "0123456789abcdef", nil }
	if got := s.Outdated(); got == "" {
		t.Fatal("another schema passes")
	}
}
