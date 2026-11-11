package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"image"
	"image/png"
	"log/slog"
	"os"
	"path/filepath"
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
	taskType, raw, err := api.AccessTask(p)
	if err != nil {
		t.Fatal(err)
	}
	if result := a.Set(context.Background(), api.Task{Type: taskType, Payload: raw}); !result.OK {
		t.Fatal(result.Output)
	}
}

func TestBlockedScreenIsLockedAgain(t *testing.T) {
	a, s := newAccess(t)
	setAccess(t, a, api.AccessPayload{Mode: api.AccessScreen, Users: []string{"anna"}})
	if calls := s.done(); !slices.Equal(calls, []string{"lock-session 3"}) {
		t.Fatalf("got %v", calls)
	}
	// anna unlocked it and set LockedHint herself, which logind lets her do:
	// the next check locks again all the same.
	s.locked["3"] = true
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
		taskType, raw, err := api.AccessTask(p)
		if err == nil {
			err = api.Validate(taskType, raw)
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// kiosk extends seat with the console, the block service and the seat in front.
type kiosk struct {
	*seat
	running bool
	front   string
	active  string
}

func newKiosk(t *testing.T) (*Access, *kiosk) {
	t.Helper()
	a, s := newAccess(t)
	k := &kiosk{seat: s, front: "tty2", active: "3"}
	tty := a.exec.path(activeTTY)
	if err := os.MkdirAll(filepath.Dir(tty), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func() { os.WriteFile(tty, []byte(k.front+"\n"), 0o644) }
	write()
	seatRun := a.exec.Run
	a.exec.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		switch {
		case name == "systemctl" && args[0] == "is-active":
			if !k.running {
				return "", errors.New("inactive")
			}
			return "", nil
		case name == "systemctl" && args[0] == "start":
			k.running = true
		case name == "systemctl" && args[0] == "stop":
			k.running = false
		case name == "chvt":
			k.front = "tty" + args[0]
			write()
		case name == "loginctl" && args[0] == "show-seat":
			return k.active + "\n", nil
		case name == "loginctl" && args[0] == "show-session" && slices.Contains(args, "Name"):
			return map[string]string{"3": "anna", "4": "ben"}[args[1]] + "\n", nil
		}
		if name == "loginctl" {
			return seatRun(ctx, name, args...)
		}
		k.mu.Lock()
		k.calls = append(k.calls, name+" "+strings.Join(args, " "))
		k.mu.Unlock()
		return "", nil
	}
	return a, k
}

func TestFullscreenBlockCoversTheScreen(t *testing.T) {
	a, k := newKiosk(t)
	picture := pngOf(t, 4, 4)
	setAccess(t, a, api.AccessPayload{Mode: api.AccessFullscreen, Message: "Abendessen!", Image: picture})
	if !k.running || k.front != blockTTY {
		t.Fatalf("running %v, front %s", k.running, k.front)
	}
	if raw, _ := os.ReadFile(a.exec.path(blockDir + "/message")); string(raw) != "Abendessen!\n" {
		t.Fatalf("message %q", raw)
	}
	if raw, _ := os.ReadFile(a.exec.path(unitPath)); !strings.Contains(string(raw), "ExecStart=/usr/bin/cage -s -- /usr/bin/hauswart-blocker") || !strings.Contains(string(raw), "BindsTo=hauswart-agent.service") {
		t.Fatalf("unit %s", raw)
	}
	if !k.locked["3"] {
		t.Fatal("the session behind it stays open")
	}
	// Someone switched away: the next check brings the block back.
	k.front = "tty2"
	os.WriteFile(a.exec.path(activeTTY), []byte("tty2\n"), 0o644)
	a.Check(context.Background())
	if k.front != blockTTY {
		t.Fatalf("front %s", k.front)
	}
	setAccess(t, a, api.AccessPayload{Mode: api.AccessOpen})
	if k.running || k.front != "tty2" {
		t.Fatalf("after opening: running %v, front %s", k.running, k.front)
	}
}

func TestFullscreenForOnePersonFollowsTheirSession(t *testing.T) {
	a, k := newKiosk(t)
	k.active = "4" // ben is in front
	setAccess(t, a, api.AccessPayload{Mode: api.AccessFullscreen, Users: []string{"anna"}})
	if k.running {
		t.Fatal("blocked while ben is in front")
	}
	k.active = "3"
	a.Check(context.Background())
	if !k.running || k.front != blockTTY {
		t.Fatalf("anna in front: running %v, front %s", k.running, k.front)
	}
}

func TestFullscreenChecks(t *testing.T) {
	for name, p := range map[string]api.AccessPayload{
		"message elsewhere": {Mode: api.AccessScreen, Message: "x"},
		"not a picture":     {Mode: api.AccessFullscreen, Image: base64.StdEncoding.EncodeToString([]byte("GIF89a"))},
		"not base64":        {Mode: api.AccessFullscreen, Image: "!!"},
		"two lines":         {Mode: api.AccessFullscreen, Message: "a\nb"},
	} {
		taskType, raw, err := api.AccessTask(p)
		if err == nil {
			err = api.Validate(taskType, raw)
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func pngOf(t *testing.T, width, height int) string {
	t.Helper()
	var out bytes.Buffer
	if err := png.Encode(&out, image.NewGray(image.Rect(0, 0, width, height))); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(out.Bytes())
}

func TestHugePictureIsRefused(t *testing.T) {
	// A PNG header that claims 40000 by 40000 pixels, in a few bytes.
	header := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR\x00\x00\x9c\x40\x00\x00\x9c\x40\x08\x00\x00\x00\x00")
	if _, err := api.AccessImage(base64.StdEncoding.EncodeToString(header)); err == nil {
		t.Fatal("a picture of 40000 by 40000 pixels was accepted")
	}
	if _, err := api.AccessImage(pngOf(t, 64, 64)); err != nil {
		t.Fatal(err)
	}
}

// A device list from before the split allows all four, as it did.
func TestLegacyAccessTypeMeansAllFour(t *testing.T) {
	cfg := Config{PasskeyTypes: []string{api.LegacyAccessSet}}
	for _, taskType := range api.AccessTypes {
		if !slices.Contains(cfg.passkeyTypes(), taskType) {
			t.Errorf("%s is not allowed", taskType)
		}
	}
}
