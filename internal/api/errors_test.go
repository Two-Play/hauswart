package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Without this, a new error code would silently show up in English in the
// German dashboard, or as a raw code.
func TestEveryErrorCodeIsTranslated(t *testing.T) {
	for _, lang := range []string{"en", "de"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "locales", lang+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var locale struct {
			Errors map[string]string `json:"errors"`
		}
		if err := json.Unmarshal(raw, &locale); err != nil {
			t.Fatal(err)
		}
		for code := range Messages {
			if locale.Errors[code] == "" {
				t.Errorf("%s: no translation for %s", lang, code)
			}
		}
		for code := range locale.Errors {
			if _, ok := Messages[code]; !ok {
				t.Errorf("%s: translation for unknown code %s", lang, code)
			}
		}
	}
}

func TestErrorMessage(t *testing.T) {
	if got := Fail(ErrInvalidUser, "root").Error(); got != "invalid user root" {
		t.Errorf("got %q", got)
	}
	if got := Fail(ErrAdminOnly).Error(); strings.Contains(got, "%") {
		t.Errorf("got %q", got)
	}
}
