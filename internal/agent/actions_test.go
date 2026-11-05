package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/philippe/hauswart/internal/api"
)

func payload(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func soon() time.Time { return time.Now().Add(time.Hour) }

// sessions fakes loginctl with the given properties per session ID.
func sessions(e *Executor, list map[string]string) *[][]string {
	var calls [][]string
	e.Run = func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, append([]string{name}, args...))
		if name != "loginctl" {
			return "", nil
		}
		if args[0] == "list-sessions" {
			var out strings.Builder
			for id := range list {
				out.WriteString(" " + id + " 1000 someone seat0 tty2 active no\n")
			}
			return out.String(), nil
		}
		return list[args[1]], nil
	}
	return &calls
}

func ordinaryUser(t *testing.T) *user.User {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if u.Uid == "0" || !api.ValidUser(u.Username) {
		t.Skip("needs an ordinary account")
	}
	return u
}

func desktopSession(name string) string {
	return "Name=" + name + "\nType=wayland\nClass=user\nState=active\nRemote=no\n"
}

func popups(calls [][]string) [][]string {
	var found [][]string
	for _, call := range calls {
		if call[0] == "runuser" {
			found = append(found, call)
		}
	}
	return found
}

func TestRebootSchedulesWithWarning(t *testing.T) {
	e, _ := newExecutor(t)
	calls := sessions(e, nil)
	result := e.Execute(context.Background(), api.Task{Type: api.TaskPowerReboot,
		Payload: payload(t, api.PowerPayload{DelayMinutes: 5, Message: "--halt", ExpiresAt: soon()})})
	if !result.OK {
		t.Fatal(result.Output)
	}
	var shutdown []string
	for _, call := range *calls {
		if call[0] == "shutdown" {
			shutdown = call
		}
	}
	want := []string{"shutdown", "-r", "+5", "Hauswart: this device will restart in 5 minute(s). --halt"}
	if !slices.Equal(shutdown, want) {
		t.Fatalf("got %q", shutdown)
	}
}

func TestShutdownPowersOff(t *testing.T) {
	e, runner := newExecutor(t)
	result := e.Execute(context.Background(), api.Task{Type: api.TaskPowerShutdown,
		Payload: payload(t, api.PowerPayload{DelayMinutes: 1, ExpiresAt: soon()})})
	if !result.OK {
		t.Fatal(result.Output)
	}
	if call := runner.calls[0]; call[0] != "shutdown" || call[1] != "-P" {
		t.Fatalf("got %q", call)
	}
}

func TestPowerRefusesAnExpiredTask(t *testing.T) {
	e, runner := newExecutor(t)
	result := e.Execute(context.Background(), api.Task{Type: api.TaskPowerReboot,
		Payload: payload(t, api.PowerPayload{DelayMinutes: 5, ExpiresAt: time.Now().Add(-time.Second)})})
	if result.OK || len(runner.calls) != 0 {
		t.Fatalf("ran an expired task: %+v %q", result, runner.calls)
	}
}

func TestPowerFailureIsReported(t *testing.T) {
	e, runner := newExecutor(t)
	runner.err = errors.New("no shutdown here")
	result := e.Execute(context.Background(), api.Task{Type: api.TaskPowerReboot,
		Payload: payload(t, api.PowerPayload{DelayMinutes: 5, ExpiresAt: soon()})})
	if result.OK {
		t.Fatal("reported success")
	}
}

func TestPowerSucceedsWithoutADesktop(t *testing.T) {
	e, runner := newExecutor(t)
	e.Run = func(_ context.Context, name string, args ...string) (string, error) {
		if name == "loginctl" {
			return "", errors.New("no logind")
		}
		return runner.run(context.Background(), name, args...)
	}
	result := e.Execute(context.Background(), api.Task{Type: api.TaskPowerReboot,
		Payload: payload(t, api.PowerPayload{DelayMinutes: 5, ExpiresAt: soon()})})
	if !result.OK {
		t.Fatal(result.Output)
	}
}

func TestCancel(t *testing.T) {
	e, _ := newExecutor(t)
	calls := sessions(e, nil)
	task := api.Task{Type: api.TaskPowerCancel, Payload: json.RawMessage(`{}`)}

	result := e.Execute(context.Background(), task)
	if !result.OK || !strings.Contains(result.Output, "nothing was scheduled") || len(*calls) != 0 {
		t.Fatalf("%+v %q", result, *calls)
	}

	marker := e.path(scheduledFile)
	if err := os.MkdirAll(filepath.Dir(marker), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	result = e.Execute(context.Background(), task)
	if !result.OK || !slices.Equal((*calls)[0], []string{"shutdown", "-c"}) {
		t.Fatalf("%+v %q", result, *calls)
	}
}

func TestPopupIsEscapedAndCarriesTheFixedTitle(t *testing.T) {
	me := ordinaryUser(t)
	e, _ := newExecutor(t)
	calls := sessions(e, map[string]string{"3": desktopSession(me.Username)})
	message := `<a href="http://evil">System</a> & more`
	result := e.Execute(context.Background(), api.Task{Type: api.TaskNotifySend,
		Payload: payload(t, api.NotifyPayload{Message: message, ExpiresAt: soon()})})
	if !result.OK {
		t.Fatal(result.Output)
	}
	sent := popups(*calls)
	if len(sent) != 1 {
		t.Fatalf("got %q", *calls)
	}
	call := sent[0]
	if !slices.Contains(call, `&lt;a href="http://evil"&gt;System&lt;/a&gt; &amp; more`) {
		t.Fatalf("not escaped: %q", call)
	}
	if !slices.Equal(call[:3], []string{"runuser", "-u", me.Username}) {
		t.Fatalf("not run as the user: %q", call)
	}
	at := slices.Index(call, "susssasa{sv}i")
	if call[at+1] != popupTitle || call[at+4] != popupTitle {
		t.Fatalf("title is not fixed: %q", call)
	}
	// Everything after "--" is an argument, whatever a message starts with.
	if at := slices.Index(call, "call"); call[at-1] != "--" {
		t.Fatalf("no end of options before the message: %q", call)
	}
}

func TestPopupSkipsWhatIsNoDesktop(t *testing.T) {
	me := ordinaryUser(t)
	for name, session := range map[string]string{
		"terminal":     strings.Replace(desktopSession(me.Username), "wayland", "tty", 1),
		"login screen": strings.Replace(desktopSession(me.Username), "Class=user", "Class=greeter", 1),
		"remote":       strings.Replace(desktopSession(me.Username), "Remote=no", "Remote=yes", 1),
		"closing":      strings.Replace(desktopSession(me.Username), "active", "closing", 1),
		"root":         desktopSession("root"),
		"unknown user": desktopSession("no-such-user"),
	} {
		e, _ := newExecutor(t)
		calls := sessions(e, map[string]string{"3": session})
		result := e.Execute(context.Background(), api.Task{Type: api.TaskNotifySend,
			Payload: payload(t, api.NotifyPayload{Message: "hello", ExpiresAt: soon()})})
		if result.OK || len(popups(*calls)) != 0 {
			t.Errorf("%s: %+v %q", name, result, *calls)
		}
	}
}

func TestPopupReachesEachPersonOnce(t *testing.T) {
	me := ordinaryUser(t)
	e, _ := newExecutor(t)
	calls := sessions(e, map[string]string{"3": desktopSession(me.Username), "7": desktopSession(me.Username)})
	result := e.Execute(context.Background(), api.Task{Type: api.TaskNotifySend,
		Payload: payload(t, api.NotifyPayload{Message: "hello", ExpiresAt: soon()})})
	if !result.OK || len(popups(*calls)) != 1 {
		t.Fatalf("%+v %q", result, *calls)
	}
}

func TestPopupForAnotherUserReachesNobodyElse(t *testing.T) {
	me := ordinaryUser(t)
	e, _ := newExecutor(t)
	calls := sessions(e, map[string]string{"3": desktopSession(me.Username)})
	result := e.Execute(context.Background(), api.Task{Type: api.TaskNotifySend,
		Payload: payload(t, api.NotifyPayload{Message: "hello", User: "someone-else", ExpiresAt: soon()})})
	if result.OK || len(popups(*calls)) != 0 {
		t.Fatalf("%+v %q", result, *calls)
	}
}

func TestNotifyRefusesAnExpiredMessage(t *testing.T) {
	e, runner := newExecutor(t)
	result := e.Execute(context.Background(), api.Task{Type: api.TaskNotifySend,
		Payload: payload(t, api.NotifyPayload{Message: "old", ExpiresAt: time.Now().Add(-time.Second)})})
	if result.OK || len(runner.calls) != 0 {
		t.Fatalf("%+v %q", result, runner.calls)
	}
}

func primaryGroup(t *testing.T) (*user.User, string) {
	t.Helper()
	me := ordinaryUser(t)
	group, err := user.LookupGroupId(me.Gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := api.Validate(api.TaskGroupAdd, payload(t, api.GroupPayload{User: me.Username, Group: group.Name})); err != nil {
		t.Skip("primary group not usable here")
	}
	return me, group.Name
}

func TestGroupChange(t *testing.T) {
	me, group := primaryGroup(t)
	e, runner := newExecutor(t)
	p := payload(t, api.GroupPayload{User: me.Username, Group: group})
	if result := e.Execute(context.Background(), api.Task{Type: api.TaskGroupAdd, Payload: p}); !result.OK {
		t.Fatal(result.Output)
	}
	if result := e.Execute(context.Background(), api.Task{Type: api.TaskGroupRemove, Payload: p}); !result.OK {
		t.Fatal(result.Output)
	}
	want := [][]string{{"gpasswd", "-a", me.Username, group}, {"gpasswd", "-d", me.Username, group}}
	if !slices.EqualFunc(runner.calls, want, slices.Equal[[]string]) {
		t.Fatalf("got %q", runner.calls)
	}
}

func TestGroupRefusesPrivilegedAndUnknown(t *testing.T) {
	me := ordinaryUser(t)
	for _, group := range []string{"wheel", "sudo", "docker", "root", "shadow", "no-such-group"} {
		e, runner := newExecutor(t)
		result := e.Execute(context.Background(), api.Task{Type: api.TaskGroupAdd,
			Payload: payload(t, api.GroupPayload{User: me.Username, Group: group})})
		if result.OK || len(runner.calls) != 0 {
			t.Errorf("%s: %+v %q", group, result, runner.calls)
		}
	}
}

func TestGroupRefusesSystemAccounts(t *testing.T) {
	_, group := primaryGroup(t)
	e, runner := newExecutor(t)
	result := e.Execute(context.Background(), api.Task{Type: api.TaskGroupAdd,
		Payload: payload(t, api.GroupPayload{User: "daemon", Group: group})})
	if result.OK || len(runner.calls) != 0 {
		t.Fatalf("%+v %q", result, runner.calls)
	}
}

func TestGroupRefusesWhatSudoersPrivileges(t *testing.T) {
	me, group := primaryGroup(t)
	for rule, refused := range map[string]bool{
		"%" + group + " ALL=(ALL) ALL\n":       true,
		"%:" + group + " ALL=(ALL) ALL\n":      true,
		"# %" + group + " ALL=(ALL) ALL\n":     false,
		"%" + group + "-other ALL=(ALL) ALL\n": false,
		"anna ALL=(ALL) ALL\n":                 false,
	} {
		e, _ := newExecutor(t)
		dir := e.path("/etc/sudoers.d")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "family"), []byte(rule), 0o440); err != nil {
			t.Fatal(err)
		}
		result := e.Execute(context.Background(), api.Task{Type: api.TaskGroupAdd,
			Payload: payload(t, api.GroupPayload{User: me.Username, Group: group})})
		if result.OK == refused {
			t.Errorf("%q: %+v", rule, result)
		}
	}
}
