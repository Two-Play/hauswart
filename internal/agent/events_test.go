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

// desktop fakes loginctl with one graphical session of the current account, and
// keeps who got which popup.
type desktop struct {
	mu    sync.Mutex
	shown []string
}

func newNotices(t *testing.T) (*Notices, *desktop, string) {
	t.Helper()
	person := ordinaryUser(t)
	e, _ := newExecutor(t)
	d := &desktop{}
	e.Run = func(_ context.Context, name string, args ...string) (string, error) {
		switch {
		case name == "loginctl" && args[0] == "list-sessions":
			return " 2 " + person.Uid + " " + person.Username + " seat0 tty2 active no\n", nil
		case name == "loginctl":
			return desktopSession(person.Username), nil
		case name == "runuser":
			d.mu.Lock()
			d.shown = append(d.shown, args[1]+": "+args[18])
			d.mu.Unlock()
		}
		return "", nil
	}
	dir := t.TempDir()
	return OpenNotices(dir, e, func() string { return "en" }, slog.New(slog.DiscardHandler)), d, person.Username
}

func (d *desktop) popups(n *Notices) []string {
	n.popups.Wait()
	d.mu.Lock()
	defer d.mu.Unlock()
	shown := d.shown
	d.shown = nil
	return shown
}

func TestTaskEvents(t *testing.T) {
	until := time.Date(2026, 11, 8, 14, 30, 0, 0, time.Local)
	for name, c := range map[string]struct {
		task   api.Task
		ok     bool
		want   api.DeviceEvent
		listed bool
	}{
		"sudo granted": {api.Task{Type: api.TaskSudoGrant, Payload: payload(t, api.SudoGrantPayload{User: "anna", ExpiresAt: until})}, true,
			api.DeviceEvent{Kind: api.EventSudoGranted, User: "anna", Until: until}, true},
		"sudo failed tells nothing": {api.Task{Type: api.TaskSudoGrant, Payload: payload(t, api.SudoGrantPayload{User: "anna"})}, false,
			api.DeviceEvent{}, false},
		"installed": {api.Task{Type: api.TaskPkgInstall, Payload: payload(t, api.PackagesPayload{Packages: []string{"vim", "git"}})}, true,
			api.DeviceEvent{Kind: api.EventSoftwareInstalled, Detail: "vim, git"}, true},
		"install failed": {api.Task{Type: api.TaskFlatpakInstall, Payload: payload(t, api.PackagesPayload{Packages: []string{"org.gimp.GIMP"}})}, false,
			api.DeviceEvent{Kind: api.EventSoftwareFailed, Detail: "org.gimp.GIMP"}, true},
		"removed": {api.Task{Type: api.TaskPkgRemove, Payload: payload(t, api.PackagesPayload{Packages: []string{"vim"}})}, true,
			api.DeviceEvent{Kind: api.EventSoftwareRemoved, Detail: "vim"}, true},
		"locked": {api.Task{Type: api.TaskUserLock, Payload: payload(t, api.UserPayload{User: "anna"})}, true,
			api.DeviceEvent{Kind: api.EventAccountLocked, User: "anna"}, true},
		"group": {api.Task{Type: api.TaskGroupAdd, Payload: payload(t, api.GroupPayload{User: "anna", Group: "media"})}, true,
			api.DeviceEvent{Kind: api.EventGroupAdded, User: "anna", Detail: "media"}, true},
		"policy": {api.Task{Type: api.TaskPolicySet, Payload: []byte(`{}`)}, true,
			api.DeviceEvent{Kind: api.EventPolicyChanged}, true},
		"screen time tells on its own": {api.Task{Type: api.TaskScreenExtend, Payload: []byte(`{}`)}, true,
			api.DeviceEvent{}, true},
		"logs tell nothing": {api.Task{Type: api.TaskLogsFetch, Payload: []byte(`{}`)}, true,
			api.DeviceEvent{}, false},
	} {
		got, listed := taskEvent(c.task, api.TaskResult{OK: c.ok})
		if listed != c.listed || got != c.want {
			t.Errorf("%s: got %+v %v", name, got, listed)
		}
	}
}

func TestEventsReachThePersonConcerned(t *testing.T) {
	n, d, me := newNotices(t)
	ctx := context.Background()
	n.AfterTask(ctx, api.Task{Type: api.TaskUserLock, Payload: payload(t, api.UserPayload{User: "someone-else"})}, api.TaskResult{OK: true})
	if shown := d.popups(n); len(shown) != 0 {
		t.Fatalf("someone else's lock reached %v", shown)
	}
	n.AfterTask(ctx, api.Task{Type: api.TaskPkgInstall, Payload: payload(t, api.PackagesPayload{Packages: []string{"vim"}})}, api.TaskResult{OK: true})
	if shown := d.popups(n); !slices.Equal(shown, []string{me + ": Installed: vim"}) {
		t.Fatalf("got %v", shown)
	}
	// The history keeps both, but shows each person only theirs and the device's.
	if h := n.History(me); len(h.Events) != 1 || h.Events[0].Kind != api.EventSoftwareInstalled {
		t.Fatalf("got %+v", h)
	}
	if h := n.History("someone-else"); len(h.Events) != 2 || h.Events[0].Kind != api.EventSoftwareInstalled {
		t.Fatalf("got %+v", h)
	}
}

func TestSudoWarningAndEnd(t *testing.T) {
	n, d, me := newNotices(t)
	ctx := context.Background()
	now := time.Now()
	n.now = func() time.Time { return now }
	end := now.Add(10 * time.Minute)
	n.CheckGrants(ctx, map[string]time.Time{me: end}, nil)
	if shown := d.popups(n); len(shown) != 0 {
		t.Fatalf("warned too early: %v", shown)
	}
	now = end.Add(-4 * time.Minute)
	for range 2 { // once per grant
		n.CheckGrants(ctx, map[string]time.Time{me: end}, nil)
	}
	if shown := d.popups(n); len(shown) != 1 || !strings.Contains(shown[0], "end at "+end.Local().Format("15:04")) {
		t.Fatalf("got %v", shown)
	}
	// More time is another grant, with a warning of its own.
	later := end.Add(time.Minute)
	n.CheckGrants(ctx, map[string]time.Time{me: later}, nil)
	if shown := d.popups(n); len(shown) != 1 {
		t.Fatalf("got %v", shown)
	}
	n.CheckGrants(ctx, map[string]time.Time{}, []string{me})
	if shown := d.popups(n); !slices.Equal(shown, []string{me + ": Your admin rights have ended."}) {
		t.Fatalf("got %v", shown)
	}
}

func TestRequestStatesTellOnce(t *testing.T) {
	n, d, me := newNotices(t)
	ctx := context.Background()
	request := func(id, kind, detail, state string) api.RequestState {
		return api.RequestState{ID: id, User: me, Kind: kind, Detail: detail, State: state}
	}
	// The first answer only sets the scene: a new agent does not repeat the past.
	n.SetRequests(ctx, []api.RequestState{request("old", api.RequestSoftware, "vim", api.RequestDenied)})
	if shown := d.popups(n); len(shown) != 0 {
		t.Fatalf("got %v", shown)
	}
	n.SetRequests(ctx, []api.RequestState{
		request("old", api.RequestSoftware, "vim", api.RequestDenied),
		request("sudo", api.RequestSudo, "30", api.RequestSigning),
		request("gimp", api.RequestFlatpak, "org.gimp.GIMP", api.RequestOpen),
	})
	if shown := d.popups(n); !slices.Equal(shown, []string{me + ": Your request for admin rights was approved and waits for a signature."}) {
		t.Fatalf("got %v", shown)
	}
	// The task of the sudo request tells by itself, so its end tells nothing more.
	n.AfterTask(ctx, api.Task{Type: api.TaskSudoGrant, Request: "sudo",
		Payload: payload(t, api.SudoGrantPayload{User: me, ExpiresAt: time.Now().Add(time.Hour)})}, api.TaskResult{OK: true})
	if shown := d.popups(n); len(shown) != 1 || !strings.Contains(shown[0], "admin rights until") {
		t.Fatalf("got %v", shown)
	}
	n.SetRequests(ctx, []api.RequestState{
		request("sudo", api.RequestSudo, "30", api.RequestDone),
		request("gimp", api.RequestFlatpak, "org.gimp.GIMP", api.RequestDenied),
	})
	if shown := d.popups(n); !slices.Equal(shown, []string{me + ": Your request for org.gimp.GIMP was denied."}) {
		t.Fatalf("got %v", shown)
	}
	if h := n.History(me); len(h.Requests) != 2 || h.Requests[1].State != api.RequestDenied {
		t.Fatalf("got %+v", h.Requests)
	}
	if h := n.History("someone-else"); len(h.Requests) != 0 {
		t.Fatalf("someone else sees %+v", h.Requests)
	}

	// A restart remembers what was told.
	again := OpenNotices(n.path[:len(n.path)-len("/"+eventsFile)], n.exec, n.language, n.log)
	again.SetRequests(ctx, []api.RequestState{request("gimp", api.RequestFlatpak, "org.gimp.GIMP", api.RequestDenied)})
	if shown := d.popups(again); len(shown) != 0 {
		t.Fatalf("told again: %v", shown)
	}
	if h := again.History(me); len(h.Events) != 1 {
		t.Fatalf("history lost: %+v", h)
	}
}

func TestBrokenHistoryStartsEmpty(t *testing.T) {
	n, _, me := newNotices(t)
	dir := n.path[:len(n.path)-len("/"+eventsFile)]
	if err := os.WriteFile(n.path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if h := OpenNotices(dir, n.exec, n.language, n.log).History(me); len(h.Events) != 0 {
		t.Fatalf("got %+v", h)
	}
}

func TestPopupsInGerman(t *testing.T) {
	if got := eventText("de", api.RequestDenied, requestName("de", api.RequestState{Kind: api.RequestSudo, Detail: "30"}), time.Time{}); got != "Deine Anfrage für Admin-Rechte wurde abgelehnt." {
		t.Fatalf("got %q", got)
	}
	if got := eventText("xx", api.EventSudoExpired, "", time.Time{}); got != "Your admin rights have ended." {
		t.Fatalf("got %q", got)
	}
}
