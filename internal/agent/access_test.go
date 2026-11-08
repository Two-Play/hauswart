package agent

import (
	"context"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

// seat fakes loginctl with sessions of two people and remembers what was done.
type seat struct {
	mu     sync.Mutex
	locked map[string]bool
	calls  []string
}

func newAccess(t *testing.T) (*Access, *seat) {
	t.Helper()
	e, _ := newExecutor(t)
	s := &seat{locked: map[string]bool{}}
	e.Run = func(_ context.Context, name string, args ...string) (string, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if name != "loginctl" {
			return "", nil
		}
		switch args[0] {
		case "list-sessions":
			return " 3 1001 anna seat0 tty2\n 4 1002 ben seat0 tty3\n 5 0 root - pts/0\n", nil
		case "show-session":
			locked := "no"
			if s.locked[args[1]] {
				locked = "yes"
			}
			return "Type=wayland\nLockedHint=" + locked + "\n", nil
		case "lock-session":
			s.locked[args[1]] = true
		}
		s.calls = append(s.calls, strings.Join(args, " "))
		return "", nil
	}
	if err := os.MkdirAll(e.path("/run"), 0o755); err != nil {
		t.Fatal(err)
	}
	return OpenAccess(t.TempDir(), e, nil, slog.New(slog.DiscardHandler)), s
}

func (s *seat) done() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	calls := s.calls
	s.calls = nil
	return calls
}

func setAccess(t *testing.T, a *Access, p api.AccessPayload) {
	t.Helper()
	if result := a.Set(context.Background(), api.Task{Type: api.TaskAccessSet, Payload: payload(t, p)}); !result.OK {
		t.Fatal(result.Output)
	}
}

func TestBlockedScreenIsLockedAgain(t *testing.T) {
	a, s := newAccess(t)
	setAccess(t, a, api.AccessPayload{Mode: api.AccessScreen, Users: []string{"anna"}})
	if calls := s.done(); !slices.Equal(calls, []string{"lock-session 3"}) {
		t.Fatalf("got %v", calls)
	}
	a.Check(context.Background())
	if calls := s.done(); len(calls) != 0 {
		t.Fatalf("locked twice: %v", calls)
	}
	s.locked["3"] = false // anna unlocked it
	a.Check(context.Background())
	if calls := s.done(); !slices.Equal(calls, []string{"lock-session 3"}) {
		t.Fatalf("got %v", calls)
	}
	if a.StatusFor("anna") == nil || a.StatusFor("ben") != nil {
		t.Fatal("the status is about the wrong people")
	}
}

func TestRefusedLoginsWarnThenEnd(t *testing.T) {
	a, s := newAccess(t)
	now := time.Now()
	a.now = func() time.Time { return now }
	setAccess(t, a, api.AccessPayload{Mode: api.AccessLogin})
	nologin := a.exec.path(nologinFile)
	if raw, err := os.ReadFile(nologin); err != nil || string(raw) != nologinText {
		t.Fatalf("no nologin: %v", err)
	}
	if calls := s.done(); len(calls) != 0 {
		t.Fatalf("ended at once: %v", calls)
	}
	now = now.Add(accessGrace)
	a.Check(context.Background())
	calls := s.done()
	slices.Sort(calls)
	if !slices.Equal(calls, []string{"terminate-user anna", "terminate-user ben"}) {
		t.Fatalf("got %v", calls)
	}
	setAccess(t, a, api.AccessPayload{Mode: api.AccessOpen})
	if _, err := os.Stat(nologin); !os.IsNotExist(err) {
		t.Fatal("nologin stayed")
	}
}

func TestSomeoneRefusedWhoLogsInLaterGoesAtOnce(t *testing.T) {
	a, s := newAccess(t)
	setAccess(t, a, api.AccessPayload{Mode: api.AccessLogin, Users: []string{"ben"}})
	if _, err := os.Stat(a.exec.path(nologinFile)); !os.IsNotExist(err) {
		t.Fatal("one person must not lock out everyone")
	}
	s.done()
	a.mu.Lock()
	a.grace = map[string]time.Time{} // ben logged out and in again
	a.mu.Unlock()
	a.Check(context.Background())
	if calls := s.done(); !slices.Equal(calls, []string{"terminate-user ben"}) {
		t.Fatalf("got %v", calls)
	}
}

func TestBlockEndsOnTimeAndSurvivesARestart(t *testing.T) {
	a, s := newAccess(t)
	now := time.Now()
	a.now = func() time.Time { return now }
	setAccess(t, a, api.AccessPayload{Mode: api.AccessLogin, Until: now.Add(time.Hour)})
	again := OpenAccess(a.path[:len(a.path)-len("/"+accessFile)], a.exec, nil, a.log)
	again.now = a.now
	if again.Current() == nil {
		t.Fatal("a restart lifted the block")
	}
	now = now.Add(time.Hour)
	again.Check(context.Background())
	if again.Current() != nil {
		t.Fatal("the block outlasted its end")
	}
	if _, err := os.Stat(a.exec.path(nologinFile)); !os.IsNotExist(err) {
		t.Fatal("nologin outlasted the block")
	}
	s.done()
}

func TestNologinOfSomeoneElseStays(t *testing.T) {
	a, _ := newAccess(t)
	if err := os.WriteFile(a.exec.path(nologinFile), []byte("maintenance\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	setAccess(t, a, api.AccessPayload{Mode: api.AccessLogin})
	setAccess(t, a, api.AccessPayload{Mode: api.AccessOpen})
	if raw, _ := os.ReadFile(a.exec.path(nologinFile)); string(raw) != "maintenance\n" {
		t.Fatalf("got %q", raw)
	}
}

func TestAccessChecks(t *testing.T) {
	for name, p := range map[string]api.AccessPayload{
		"unknown mode":   {Mode: "shell"},
		"open with user": {Mode: api.AccessOpen, Users: []string{"anna"}},
		"past end":       {Mode: api.AccessScreen, Until: time.Now().Add(-time.Minute)},
		"too far":        {Mode: api.AccessScreen, Until: time.Now().Add(api.MaxAccessBlock + time.Hour)},
		"bad user":       {Mode: api.AccessLogin, Users: []string{"../x"}},
		"twice":          {Mode: api.AccessLogin, Users: []string{"anna", "anna"}},
	} {
		if err := api.Validate(api.TaskAccessSet, payload(t, p)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
