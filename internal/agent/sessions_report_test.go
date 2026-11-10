package agent

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/Two-Play/hauswart/internal/api"
)

func TestReportNamesLoggedInUsers(t *testing.T) {
	e, _ := newExecutor(t)
	e.Run = func(_ context.Context, name string, args ...string) (string, error) {
		switch {
		case name == "loginctl" && args[0] == "list-sessions":
			return " 3 1000 anna seat0 tty2 active no\n 4 1001 ben seat0 tty3 online no\n 5 1000 anna - pts/0 active no\n", nil
		case name == "loginctl" && args[0] == "show-seat":
			return "4\n", nil
		case name == "loginctl" && args[0] == "show-session":
			return "ben\n", nil
		}
		return "", nil
	}
	got := e.sessionReport(context.Background())
	want := []api.LoginSession{{User: "anna"}, {User: "ben", Active: true}}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestReportWithoutLoginctl(t *testing.T) {
	e, _ := newExecutor(t)
	e.Run = func(context.Context, string, ...string) (string, error) { return "", errors.New("no systemd") }
	if got := e.sessionReport(context.Background()); got != nil {
		t.Fatalf("got %+v", got)
	}
}
