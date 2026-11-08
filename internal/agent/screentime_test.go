package agent

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

// loginSystem fakes loginctl for one logged in user.
type loginSystem struct {
	mu       sync.Mutex
	user     string
	uid      string
	calls    [][]string
	failStop bool
	// accounts are what getent knows, by name.
	accounts map[string]string
}

func (l *loginSystem) run(_ context.Context, name string, args ...string) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, append([]string{name}, args...))
	if name == "getent" {
		if uid, ok := l.accounts[args[1]]; ok {
			return args[1] + ":*:" + uid + ":" + uid + "::/home/x:/bin/bash\n", nil
		}
		return "", errors.New("exit status 2")
	}
	if name != "loginctl" {
		return "", nil
	}
	switch args[0] {
	case "list-sessions":
		if l.user == "" {
			return "", nil
		}
		return "7 " + l.uid + " " + l.user + " seat0 tty2\n", nil
	case "show-session":
		return "Name=" + l.user + "\nType=wayland\nClass=user\nState=active\nRemote=no\n", nil
	case "terminate-user":
		if l.failStop {
			return "denied", errors.New("exit status 1")
		}
		l.user = ""
	}
	return "", nil
}

func (l *loginSystem) count(args ...string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, call := range l.calls {
		if slices.Equal(call, append([]string{"loginctl"}, args...)) {
			n++
		}
	}
	return n
}

func (l *loginSystem) popups() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var texts []string
	for _, call := range l.calls {
		if call[0] == "runuser" {
			texts = append(texts, call[len(call)-7])
		}
	}
	return texts
}

// tick is one screen time check, and waits for its popups.
func tick(pe *PolicyEngine, now time.Time) {
	pe.checkScreenTime(context.Background(), now)
	pe.popups.Wait()
}

// 2026-11-09 is a Monday.
func monday(hour, minute int) time.Time {
	return time.Date(2026, 11, 9, hour, minute, 0, 0, time.UTC)
}

// newScreenEngine needs a real account, as the agent looks up the user.
func newScreenEngine(t *testing.T) (*PolicyEngine, *loginSystem, string) {
	t.Helper()
	pe, _ := newEngine(t)
	name := currentUser(t)
	me, err := user.Lookup(name)
	if err != nil || me.Uid < "1000" {
		t.Skip("test needs an ordinary account")
	}
	system := &loginSystem{uid: me.Uid}
	pe.exec.Run = system.run
	setPolicy(t, pe, api.Policy{
		TimeZone: "UTC",
		ScreenTime: []api.ScreenTimeRule{{User: name, Windows: []api.Window{
			{Days: []string{"mon"}, Start: "15:00", End: "19:00"},
		}}},
	})
	// The agent has seen these rules with nobody logged in, so whoever shows up
	// from here on is a new login.
	tick(pe, monday(1, 0))
	system.user = name
	return pe, system, name
}

func TestSessionEnd(t *testing.T) {
	rule := api.ScreenTimeRule{User: "anna", Windows: []api.Window{
		{Days: []string{"mon"}, Start: "15:00", End: "17:00"},
		{Days: []string{"mon"}, Start: "17:00", End: "19:00"},
		{Days: []string{"mon"}, Start: "22:00", End: "24:00"},
		{Days: []string{"tue"}, Start: "00:00", End: "01:00"},
	}}
	cases := []struct {
		name      string
		now       time.Time
		extension time.Time
		end       time.Time
		ok        bool
	}{
		{"before", monday(14, 0), time.Time{}, time.Time{}, false},
		{"touching windows are one", monday(16, 0), time.Time{}, monday(19, 0), true},
		{"after", monday(19, 0), time.Time{}, time.Time{}, false},
		{"across midnight", monday(23, 0), time.Time{}, monday(25, 0), true},
		{"extension outside a window", monday(20, 0), monday(21, 0), monday(21, 0), true},
		{"extension that ended", monday(20, 0), monday(19, 30), time.Time{}, false},
		{"extension beyond a window", monday(18, 0), monday(20, 0), monday(20, 0), true},
		{"extension up to the next window", monday(21, 0), monday(22, 30), monday(25, 0), true},
	}
	for _, c := range cases {
		end, ok := sessionEnd(rule, c.now, c.extension)
		if ok != c.ok || (ok && !end.Equal(c.end)) {
			t.Errorf("%s: got %v %v", c.name, end, ok)
		}
	}
}

// Such a rule has no end, and the check has to come back all the same.
func TestWholeWeekHasAnEndToTheSearch(t *testing.T) {
	days := []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
	rule := api.ScreenTimeRule{User: "anna", Windows: []api.Window{{Days: days, Start: "00:00", End: "24:00"}}}
	done := make(chan bool)
	go func() {
		_, ok := sessionEnd(rule, monday(12, 0), time.Time{})
		done <- ok
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("the whole week does not count as allowed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the check never came back")
	}
}

func TestNewRulesGiveAWorkingUserALockAndAMinute(t *testing.T) {
	pe, system, name := newScreenEngine(t)
	p := *pe.policy
	setPolicy(t, pe, p) // arrives while they are logged in, outside the window
	tick(pe, monday(20, 0))
	if system.count("terminate-user", name) != 0 || system.count("lock-session", "7") != 1 {
		t.Fatalf("got %v", system.calls)
	}
	tick(pe, monday(20, 1))
	if system.count("terminate-user", name) != 1 {
		t.Fatalf("got %v", system.calls)
	}
}

func TestRestartOfTheAgentGivesALockAndAMinute(t *testing.T) {
	pe, system, name := newScreenEngine(t)
	reopened := OpenPolicy(pe.dir, pe.exec, quiet())
	tick(reopened, monday(20, 0))
	if system.count("terminate-user", name) != 0 || system.count("lock-session", "7") != 1 {
		t.Fatalf("got %v", system.calls)
	}
}

func TestNoWindowMeansNoSession(t *testing.T) {
	if _, ok := sessionEnd(api.ScreenTimeRule{User: "anna"}, monday(12, 0), time.Time{}); ok {
		t.Fatal("a rule without windows let someone in")
	}
}

func TestWarningsThenLockThenEnd(t *testing.T) {
	pe, system, _ := newScreenEngine(t)

	tick(pe, monday(16, 0))
	if len(system.popups()) != 0 {
		t.Fatalf("warned too early: %v", system.popups())
	}
	tick(pe, monday(18, 45))
	tick(pe, monday(18, 46))
	tick(pe, monday(18, 55))
	tick(pe, monday(18, 59))
	popups := system.popups()
	if len(popups) != 3 || !strings.HasPrefix(popups[0], "15 minute") || !strings.HasPrefix(popups[1], "5 minute") || !strings.HasPrefix(popups[2], "1 minute") {
		t.Fatalf("got %q", popups)
	}

	tick(pe, monday(19, 0))
	if system.count("lock-session", "7") != 1 {
		t.Fatalf("not locked: %v", system.calls)
	}
	if system.user == "" {
		t.Fatal("ended without the grace period")
	}
	tick(pe, monday(19, 0).Add(30*time.Second))
	if system.user == "" {
		t.Fatal("ended before the grace period was over")
	}
	tick(pe, monday(19, 1))
	if system.user != "" {
		t.Fatal("the session goes on")
	}
}

func TestLoginOutsideTheWindowEndsAtOnce(t *testing.T) {
	pe, system, name := newScreenEngine(t)
	tick(pe, monday(20, 0))
	if system.count("terminate-user", name) != 1 {
		t.Fatalf("got %v", system.calls)
	}
	if system.count("lock-session", "7") != 0 || len(system.popups()) != 0 {
		t.Fatalf("no time to warn anyone: %v", system.calls)
	}
}

// Otherwise logging out and in again would earn another minute every time.
func TestLoggingInAgainEarnsNoGrace(t *testing.T) {
	pe, system, name := newScreenEngine(t)
	tick(pe, monday(18, 59))
	tick(pe, monday(19, 0))
	tick(pe, monday(19, 1))
	system.user = name
	tick(pe, monday(19, 2))
	if system.user != "" {
		t.Fatal("a new login got a grace period")
	}
}

func TestLoginWithLittleTimeLeftGetsTheRightWarning(t *testing.T) {
	pe, system, _ := newScreenEngine(t)
	tick(pe, monday(18, 57))
	popups := system.popups()
	if len(popups) != 1 || !strings.HasPrefix(popups[0], "3 minute") {
		t.Fatalf("got %q", popups)
	}
}

func TestFailureToEndASessionIsReported(t *testing.T) {
	pe, system, _ := newScreenEngine(t)
	system.failStop = true
	tick(pe, monday(20, 0))
	status := pe.Status()
	if len(status.Deviations) != 1 || status.Deviations[0].Kind != deviationScreen {
		t.Fatalf("got %+v", status)
	}
}

func TestSomeoneElseIsLeftAlone(t *testing.T) {
	pe, system, name := newScreenEngine(t)
	system.user, system.uid = "root", "0"
	tick(pe, monday(20, 0))
	if system.count("terminate-user", name) != 0 || system.count("terminate-user", "root") != 0 {
		t.Fatalf("got %v", system.calls)
	}
}

func TestSystemAccountsAreNeverEnded(t *testing.T) {
	pe, system, _ := newScreenEngine(t)
	setPolicy(t, pe, api.Policy{TimeZone: "UTC", ScreenTime: []api.ScreenTimeRule{{User: "daemon"}}})
	system.user, system.uid = "daemon", "2"
	tick(pe, monday(20, 0))
	if system.count("terminate-user", "daemon") != 0 {
		t.Fatal("ended a system account")
	}
}

// A member renames their Authentik account. The ID stays, and with it the rule.
func TestRenamingAnAccountLeadsNowhere(t *testing.T) {
	pe, system, _ := newScreenEngine(t)
	system.accounts = map[string]string{"mia": "2007"}
	setPolicy(t, pe, api.Policy{TimeZone: "UTC", ScreenTime: []api.ScreenTimeRule{{User: "mia"}}})
	system.user, system.uid = "", ""
	tick(pe, monday(1, 0)) // seen with nobody logged in, which keeps the ID

	delete(system.accounts, "mia")
	system.accounts["free-at-last"] = "2007"
	system.user, system.uid = "free-at-last", "2007"
	tick(pe, monday(20, 0))
	if system.count("terminate-user", "free-at-last") != 1 {
		t.Fatalf("the new name got out of the rule: %v", system.calls)
	}

	// The ID survives a restart as well.
	system.user = "free-at-last"
	reopened := OpenPolicy(pe.dir, pe.exec, quiet())
	tick(reopened, monday(1, 0))
	tick(reopened, monday(20, 1))
	if system.count("terminate-user", "free-at-last") != 2 {
		t.Fatalf("got %v", system.calls)
	}
}

// A local account that was created again has another ID, and the same name.
func TestRuleFollowsTheNameAsWell(t *testing.T) {
	pe, system, _ := newScreenEngine(t)
	system.accounts = map[string]string{"mia": "2007"}
	setPolicy(t, pe, api.Policy{TimeZone: "UTC", ScreenTime: []api.ScreenTimeRule{{User: "mia"}}})
	system.user, system.uid = "", ""
	tick(pe, monday(1, 0))
	system.accounts["mia"] = "2020"
	system.user, system.uid = "mia", "2020"
	tick(pe, monday(20, 0))
	if system.count("terminate-user", "mia") != 1 {
		t.Fatalf("got %v", system.calls)
	}
}

func TestExtension(t *testing.T) {
	pe, system, name := newScreenEngine(t)
	ctx := context.Background()
	now := monday(19, 0)

	if _, err := pe.Extend(ctx, api.ScreenExtendPayload{User: name, Until: monday(19, 30)}, now); err != nil {
		t.Fatal(err)
	}
	tick(pe, monday(19, 10))
	if system.count("lock-session", "7") != 0 {
		t.Fatal("the extension did not count")
	}
	// It outlives a restart, and the warnings count down to its end.
	reopened := OpenPolicy(pe.dir, pe.exec, quiet())
	tick(reopened, monday(19, 16))
	if popups := system.popups(); len(popups) == 0 || !strings.HasPrefix(popups[len(popups)-1], "14 minute") {
		t.Fatalf("got %q", popups)
	}
	tick(reopened, monday(19, 30))
	if system.count("lock-session", "7") != 1 {
		t.Fatal("the extension never ended")
	}
}

func TestAShorterExtensionTakesNothingAway(t *testing.T) {
	pe, _, name := newScreenEngine(t)
	ctx := context.Background()
	now := monday(19, 0)
	if _, err := pe.Extend(ctx, api.ScreenExtendPayload{User: name, Until: monday(21, 0)}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pe.Extend(ctx, api.ScreenExtendPayload{User: name, Until: monday(20, 0)}, now); err != nil {
		t.Fatal(err)
	}
	if got := pe.state.Extensions[name]; !got.Equal(monday(21, 0)) {
		t.Fatalf("got %v", got)
	}
}

func TestExtensionLimits(t *testing.T) {
	pe, _, name := newScreenEngine(t)
	ctx := context.Background()
	now := monday(18, 0)
	for label, p := range map[string]api.ScreenExtendPayload{
		"past":         {User: name, Until: now.Add(-time.Minute)},
		"too long":     {User: name, Until: now.Add(api.MaxExtension + time.Minute)},
		"unknown user": {User: "nobody2", Until: now.Add(time.Hour)},
	} {
		if _, err := pe.Extend(ctx, p, now); err == nil {
			t.Errorf("%s: accepted", label)
		}
	}
	late := monday(23, 0)
	if _, err := pe.Extend(ctx, api.ScreenExtendPayload{User: name, Until: late.Add(90 * time.Minute)}, late); err == nil {
		t.Error("an extension went past midnight")
	}
}

func TestExtensionUsesThePolicyZoneForMidnight(t *testing.T) {
	pe, _, name := newScreenEngine(t)
	p := *pe.policy
	p.TimeZone = "Asia/Tokyo"
	setPolicy(t, pe, p)
	// 14:30 UTC is 23:30 in Tokyo, so one hour reaches the next day there.
	now := monday(14, 30)
	if _, err := pe.Extend(context.Background(), api.ScreenExtendPayload{User: name, Until: now.Add(time.Hour)}, now); err == nil {
		t.Fatal("used the wrong midnight")
	}
}

func TestGermanWarnings(t *testing.T) {
	pe, system, _ := newScreenEngine(t)
	p := *pe.policy
	p.Language = "de"
	setPolicy(t, pe, p)
	tick(pe, monday(18, 45))
	if popups := system.popups(); len(popups) != 1 || !strings.HasPrefix(popups[0], "Noch 15 Minute") {
		t.Fatalf("got %q", popups)
	}
}

func TestEnforcesFirewall(t *testing.T) {
	pe, _ := newEngine(t)
	var calls []string
	active := false
	pe.exec.Run = func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		calls = append(calls, line)
		if strings.Contains(line, "is-active --quiet firewalld") && !active {
			return "", errors.New("exit status 3")
		}
		if strings.Contains(line, "enable --now firewalld") {
			active = true
		}
		return "", nil
	}
	pe.exec.Platform.Firewall = firewallD
	setPolicy(t, pe, api.Policy{Security: &api.SecurityRule{Firewall: true}})
	pe.Enforce(context.Background())
	status := pe.Status()
	if status.Checks["firewall"] != checkOn || !slices.Contains(status.Corrected, "firewall") {
		t.Fatalf("got %+v", status)
	}
	calls = nil
	pe.Enforce(context.Background())
	if slices.ContainsFunc(calls, func(c string) bool { return strings.Contains(c, "enable") }) {
		t.Fatalf("touched a running firewall: %v", calls)
	}
}

func TestUFWKeepsSSHReachable(t *testing.T) {
	pe, _ := newEngine(t)
	var calls []string
	pe.exec.Run = func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "ufw" && args[0] == "status" {
			return "Status: inactive", nil
		}
		return "", nil
	}
	pe.exec.Platform.Firewall = firewallUFW
	setPolicy(t, pe, api.Policy{Security: &api.SecurityRule{Firewall: true}})
	pe.Enforce(context.Background())
	allow := slices.Index(calls, "ufw allow 22/tcp")
	enable := slices.Index(calls, "ufw --force enable")
	if allow < 0 || enable < allow {
		t.Fatalf("got %v", calls)
	}
}

func TestMissingFirewallIsReportedNotInstalled(t *testing.T) {
	pe, system := newEngine(t)
	setPolicy(t, pe, api.Policy{Security: &api.SecurityRule{Firewall: true}})
	pe.Enforce(context.Background())
	if status := pe.Status(); status.Checks["firewall"] != checkOff || len(status.Deviations) != 1 {
		t.Fatalf("got %+v", status)
	}
	if slices.ContainsFunc(system.calls, func(c []string) bool { return c[0] == "dnf5" }) {
		t.Fatal("installed something on its own")
	}
}

func TestUFWUsesTheConfiguredSSHPort(t *testing.T) {
	e, _ := newExecutor(t)
	e.Run = func(_ context.Context, name string, _ ...string) (string, error) {
		return "port 2222\nport 22\naddressfamily any\nport evil\n", nil
	}
	if got := e.sshPorts(context.Background()); !slices.Equal(got, []string{"2222", "22"}) {
		t.Fatalf("got %v", got)
	}
}

func TestPolicyFindsAFirewallItInstalled(t *testing.T) {
	pe, _ := newEngine(t)
	var calls []string
	pe.exec.Has = func(name string) bool { return name == "firewall-cmd" }
	pe.exec.Run = func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "", nil
	}
	setPolicy(t, pe, api.Policy{Security: &api.SecurityRule{Firewall: true}})
	pe.Enforce(context.Background())
	if status := pe.Status(); status.Checks["firewall"] != checkOn {
		t.Fatalf("got %+v", status)
	}
}

func TestDiskEncryption(t *testing.T) {
	cases := []struct {
		source, types, want string
	}{
		{"/dev/mapper/luks-1", "crypt\npart\ndisk\n", checkOn},
		{"/dev/mapper/luks-1[/root]", "crypt\npart\ndisk\n", checkOn},
		{"/dev/mapper/vg-root", "lvm\ncrypt\npart\ndisk\n", checkOn},
		{"/dev/nvme0n1p3", "part\ndisk\n", checkOff},
		{"overlay", "", checkUnknown},
	}
	for _, c := range cases {
		e, _ := newExecutor(t)
		var asked string
		e.Run = func(_ context.Context, name string, args ...string) (string, error) {
			if name == "findmnt" {
				return c.source + "\n", nil
			}
			asked = args[len(args)-1]
			return c.types, nil
		}
		if got := e.diskEncryption(context.Background()); got != c.want {
			t.Errorf("%s: got %s", c.source, got)
		}
		if strings.Contains(asked, "[") {
			t.Errorf("%s: asked lsblk about %s", c.source, asked)
		}
	}
}

func TestKDELock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kscreenlockerrc")
	if got := kdeLock(path); got != checkOn {
		t.Errorf("default: got %s", got)
	}
	if err := os.WriteFile(path, []byte("[Daemon]\nAutolock=false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := kdeLock(path); got != checkOff {
		t.Errorf("off: got %s", got)
	}
	if err := os.WriteFile(path, []byte("[Greeter]\nAutolock=false\n[Daemon]\nTimeout=5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := kdeLock(path); got != checkOn {
		t.Errorf("other section: got %s", got)
	}
}

// The file is under the control of whoever the check is about.
func TestKDELockIsNotFooledByTheHomeDirectory(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(pipe, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/dev/zero", link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{pipe, link} {
		done := make(chan string)
		go func() { done <- kdeLock(path) }()
		select {
		case got := <-done:
			if got != checkUnknown {
				t.Errorf("%s: got %s", path, got)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: stuck", path)
		}
	}
}

// Measured on Fedora: an automatic login leaves Desktop empty.
func TestDesktopIsFoundWithoutItsName(t *testing.T) {
	e, _ := newExecutor(t)
	var asked []string
	e.Run = func(_ context.Context, name string, args ...string) (string, error) {
		asked = append(asked, name)
		switch {
		case name == "pgrep" && args[len(args)-1] == "gnome-shell":
			return "42", nil
		case name == "pgrep":
			return "", errors.New("exit status 1")
		case name == "runuser" && args[len(args)-1] == "lock-enabled":
			return "true\n", nil
		}
		return "uint32 300\n", nil
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if got := e.sessionLock(context.Background(), graphicalSession{person: me}); got != checkOn {
		t.Fatalf("got %s after %v", got, asked)
	}
}

func TestScreenLockWithoutASessionIsUnknown(t *testing.T) {
	pe, _ := newEngine(t)
	pe.exec.Run = (&loginSystem{}).run
	setPolicy(t, pe, api.Policy{Security: &api.SecurityRule{ScreenLock: true}})
	pe.Enforce(context.Background())
	if status := pe.Status(); status.Checks["screen_lock"] != checkUnknown || len(status.Deviations) != 0 {
		t.Fatalf("got %+v", status)
	}
}

func TestRuleEndWithQuota(t *testing.T) {
	quota := api.ScreenTimeRule{User: "anna", DailyMinutes: 120}
	now := monday(16, 0)
	if end, ok := ruleEnd(quota, now, time.Time{}, 30*time.Minute); !ok || !end.Equal(now.Add(90*time.Minute)) {
		t.Fatalf("all day with 90 minutes left: %v %v", end, ok)
	}
	if _, ok := ruleEnd(quota, now, time.Time{}, 2*time.Hour); ok {
		t.Fatal("the quota is used up")
	}
	if end, ok := ruleEnd(quota, now, now.Add(20*time.Minute), 2*time.Hour); !ok || !end.Equal(now.Add(20*time.Minute)) {
		t.Fatalf("an extension goes beyond the quota: %v %v", end, ok)
	}
	windowed := api.ScreenTimeRule{User: "anna", DailyMinutes: 120,
		Windows: []api.Window{{Days: []string{"mon"}, Start: "15:00", End: "17:00"}}}
	if end, ok := ruleEnd(windowed, now, time.Time{}, 0); !ok || !end.Equal(monday(17, 0)) {
		t.Fatalf("the window ends first: %v %v", end, ok)
	}
	if _, ok := ruleEnd(windowed, monday(18, 0), time.Time{}, 0); ok {
		t.Fatal("outside the window the quota does not help")
	}
	if _, ok := ruleEnd(api.ScreenTimeRule{User: "anna"}, now, time.Time{}, 0); ok {
		t.Fatal("no windows and no quota is no session")
	}
}

func TestQuotaCountsTimeAtTheDesktop(t *testing.T) {
	pe, system, name := newScreenEngine(t)
	setPolicy(t, pe, api.Policy{TimeZone: "UTC", ScreenTime: []api.ScreenTimeRule{{User: name, DailyMinutes: 1}}})
	at := monday(10, 0)
	for range 4 { // a minute of ticks: the first only starts counting
		tick(pe, at)
		at = at.Add(screenTick)
	}
	if used := pe.usedToday(system.uid, at); used != 45*time.Second {
		t.Fatalf("counted %v", used)
	}
	tick(pe, at)
	tick(pe, at.Add(screenTick))
	if status := pe.ScreenStatus(system.uid, at.Add(screenTick)); status == nil || status.Allowed {
		t.Fatalf("the minute is used up: %+v", status)
	}
	// A suspended device counts nothing for the time it was away, and a new day starts at zero.
	tick(pe, at.Add(time.Hour))
	if used := pe.usedToday(system.uid, at.Add(24*time.Hour)); used != 0 {
		t.Fatalf("a new day starts with %v", used)
	}
}
