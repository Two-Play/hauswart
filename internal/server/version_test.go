package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Two-Play/hauswart/internal/api"
)

func TestVersionNamesTheSchema(t *testing.T) {
	e := setup(t)
	code, data := e.do(e.login("admin"), "GET", "/api/version", nil)
	if code != http.StatusOK || !strings.Contains(string(data), api.Schema()) {
		t.Fatalf("got %d %s", code, data)
	}
	if code, _ := e.do(e.client(), "GET", "/api/version", nil); code != http.StatusUnauthorized {
		t.Fatalf("without a login: %d", code)
	}
}
