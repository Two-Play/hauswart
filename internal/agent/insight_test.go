package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

func entry(t *testing.T, fields map[string]any) string {
	t.Helper()
	all := map[string]any{"MESSAGE": "hello", "__REALTIME_TIMESTAMP": "1762300000000000", "PRIORITY": "4"}
	for name, value := range fields {
		all[name] = value
	}
	raw, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw) + "\n"
}

func TestUserMessagesStayOut(t *testing.T) {
	for name, c := range map[string]struct {
		fields map[string]any
		keep   bool
	}{
		"system service":      {map[string]any{"_UID": "0", "_SYSTEMD_UNIT": "sshd.service", "_SYSTEMD_SLICE": "system.slice"}, true},
		"service account":     {map[string]any{"_UID": "998", "_SYSTEMD_SLICE": "system.slice"}, true},
		"service as nobody":   {map[string]any{"_UID": "65534", "_SYSTEMD_SLICE": "system.slice"}, true},
		"kernel":              {map[string]any{"_TRANSPORT": "kernel"}, true},
		"journald itself":     {map[string]any{"_TRANSPORT": "driver"}, true},
		"login uid unset":     {map[string]any{"_UID": "0", "_SYSTEMD_SLICE": "system.slice", "_AUDIT_LOGINUID": "4294967295"}, true},
		"pid 1":               {map[string]any{"_UID": "0", "_SYSTEMD_SLICE": "-.slice", "_SYSTEMD_UNIT": "init.scope"}, true},
		"user process":        {map[string]any{"_UID": "1000"}, false},
		"user unit":           {map[string]any{"_UID": "0", "_SYSTEMD_USER_UNIT": "app.service"}, false},
		"user slice":          {map[string]any{"_UID": "0", "_SYSTEMD_USER_SLICE": "app.slice"}, false},
		"root in a session":   {map[string]any{"_UID": "0", "_SYSTEMD_SLICE": "user-1000.slice"}, false},
		"root's own session":  {map[string]any{"_UID": "0", "_SYSTEMD_SLICE": "user-0.slice"}, false},
		"session owner":       {map[string]any{"_UID": "0", "_SYSTEMD_OWNER_UID": "1000"}, false},
		"logged in user":      {map[string]any{"_UID": "0", "_AUDIT_LOGINUID": "1000"}, false},
		"about a user unit":   {map[string]any{"_UID": "0", "OBJECT_SYSTEMD_USER_UNIT": "app.service"}, false},
		"about a user":        {map[string]any{"_UID": "0", "OBJECT_UID": "1000"}, false},
		"crash of a user app": {map[string]any{"_UID": "0", "COREDUMP_UID": "1000"}, false},
		"uid not a number":    {map[string]any{"_UID": "x"}, false},
		"uid twice":           {map[string]any{"_UID": []string{"0", "1000"}}, false},
		"uid empty":           {map[string]any{"_UID": nil}, false},
		"no sender":           {map[string]any{"_TRANSPORT": "journal"}, false},
		"gone before a look":  {map[string]any{"_UID": "0", "_TRANSPORT": "stdout"}, false},
	} {
		entries, withheld := parseJournal(entry(t, c.fields))
		if kept := len(entries) == 1; kept != c.keep || (withheld == 1) == c.keep {
			t.Errorf("%s: kept %v, withheld %d", name, kept, withheld)
		}
	}
}

func TestParseJournal(t *testing.T) {
	out := "Hint: not an entry\n" +
		entry(t, map[string]any{"_UID": "0", "_SYSTEMD_SLICE": "system.slice", "MESSAGE": "first\nline\x1b[31m", "_SYSTEMD_UNIT": "a.service"}) +
		entry(t, map[string]any{"_UID": "0", "_SYSTEMD_SLICE": "system.slice", "MESSAGE": []int{104, 105, 255}, "SYSLOG_IDENTIFIER": "b"}) +
		entry(t, map[string]any{"_UID": "0", "_SYSTEMD_SLICE": "system.slice", "MESSAGE": nil}) +
		entry(t, map[string]any{"_UID": "0", "_SYSTEMD_SLICE": "system.slice", "MESSAGE": strings.Repeat("ä", maxLogMessage)})
	entries, _ := parseJournal(out)
	if len(entries) != 3 {
		t.Fatalf("got %d entries: %+v", len(entries), entries)
	}
	first := entries[0]
	if first.Message != "first line [31m" || first.Source != "a.service" || first.Priority != 4 {
		t.Errorf("got %+v", first)
	}
	if !first.Time.Equal(time.UnixMicro(1762300000000000)) {
		t.Errorf("time %v", first.Time)
	}
	if entries[1].Message != "hi�" || entries[1].Source != "b" {
		t.Errorf("got %+v", entries[1])
	}
	if long := entries[2].Message; len(long) > maxLogMessage+len("…") || !strings.HasSuffix(long, "…") || strings.ContainsRune(long, '�') {
		t.Errorf("not cut cleanly: %d bytes", len(long))
	}
}

func TestLogsFetchAsksOnlyForTheSystem(t *testing.T) {
	e, _ := newExecutor(t)
	var calls [][]string
	e.Run = func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, append([]string{name}, args...))
		out := entry(t, map[string]any{"_UID": "0", "_SYSTEMD_SLICE": "system.slice", "MESSAGE": "system"})
		out += entry(t, map[string]any{"_UID": "0", "_SYSTEMD_SLICE": "system.slice", "MESSAGE": "system two"})
		return out + entry(t, map[string]any{"_UID": "1000", "MESSAGE": "private"}), nil
	}
	result := e.Execute(context.Background(), task(t, api.TaskLogsFetch, api.LogsPayload{Lines: 1}))
	if !result.OK {
		t.Fatal(result.Output)
	}
	if len(calls) != 2 {
		t.Fatalf("calls %v", calls)
	}
	for _, call := range calls {
		if call[0] != "journalctl" || !slices.Contains(call, "--system") || !slices.Contains(call, "--lines=4") {
			t.Errorf("call %v", call)
		}
	}
	if !slices.Contains(calls[0], "--unit=hauswart-agent.service") || !slices.Contains(calls[1], "--priority=warning") {
		t.Errorf("calls %v", calls)
	}
	var logs api.LogsResult
	if err := json.Unmarshal(result.Data, &logs); err != nil {
		t.Fatal(err)
	}
	if !logs.Available || logs.Withheld != 2 || len(logs.System) != 1 || logs.System[0].Message != "system two" {
		t.Errorf("got %+v", logs)
	}
	if strings.Contains(string(result.Data), "private") {
		t.Error("user message in the result")
	}
}

func TestLogsFetchDefaultLength(t *testing.T) {
	e, _ := newExecutor(t)
	var args []string
	e.Run = func(_ context.Context, _ string, a ...string) (string, error) {
		args = a
		return "", nil
	}
	if result := e.Execute(context.Background(), task(t, api.TaskLogsFetch, struct{}{})); !result.OK {
		t.Fatal(result.Output)
	}
	if want := fmt.Sprintf("--lines=%d", api.DefaultLogLines*logOverfetch); !slices.Contains(args, want) {
		t.Errorf("args %v", args)
	}
}

func TestLogsResultStaysSmall(t *testing.T) {
	entries := make([]api.LogEntry, api.MaxLogLines)
	for i := range entries {
		entries[i].Message = strings.Repeat("x", maxLogMessage)
	}
	entries[len(entries)-1].Message = "newest"
	kept := newestEntries(entries, api.MaxLogLines)
	if len(kept) == 0 || len(kept) >= len(entries) || kept[len(kept)-1].Message != "newest" {
		t.Errorf("kept %d", len(kept))
	}
	if kept := newestEntries(entries, 2); len(kept) != 2 {
		t.Errorf("kept %d of 2", len(kept))
	}
}

func TestLogsWithoutJournal(t *testing.T) {
	for name, run := range map[string]func() (string, error){
		"no journalctl": func() (string, error) { return "", exec.ErrNotFound },
		"no files":      func() (string, error) { return "No journal files were found.\n", errors.New("exit status 1") },
		"no files, ok":  func() (string, error) { return "No journal files were found.\n-- No entries --\n", nil },
	} {
		e, _ := newExecutor(t)
		e.Run = func(context.Context, string, ...string) (string, error) { return run() }
		result := e.Execute(context.Background(), task(t, api.TaskLogsFetch, struct{}{}))
		var logs api.LogsResult
		if err := json.Unmarshal(result.Data, &logs); err != nil || !result.OK || logs.Available {
			t.Errorf("%s: %+v, %v", name, result, err)
		}
	}
	silent := func(context.Context, string, ...string) (string, error) { return "", nil }
	e, _ := newExecutor(t)
	e.Run = silent
	var logs api.LogsResult
	if result := e.Execute(context.Background(), task(t, api.TaskLogsFetch, struct{}{})); json.Unmarshal(result.Data, &logs) != nil || logs.Available {
		t.Errorf("silent without files: %+v", result)
	}
	writeFile(t, e.Root, "/run/log/journal/abc/system.journal", "")
	if result := e.Execute(context.Background(), task(t, api.TaskLogsFetch, struct{}{})); json.Unmarshal(result.Data, &logs) != nil || !logs.Available {
		t.Errorf("a journal with nothing to show is still a journal: %+v", result)
	}

	e, _ = newExecutor(t)
	e.Run = func(context.Context, string, ...string) (string, error) { return "broken", errors.New("exit status 1") }
	if result := e.Execute(context.Background(), task(t, api.TaskLogsFetch, struct{}{})); result.OK {
		t.Error("a real failure must show")
	}
}

const testPasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:2:2:daemon:/sbin:/usr/sbin/nologin
anna:x:1000:1000:Anna Test:/home/anna:/bin/bash
ben:x:1001:1001::/home/ben:/bin/bash
nobody:x:65534:65534:Kernel Overflow User:/:/usr/sbin/nologin
broken:x:notanumber:1:::
`

const testGroup = `root:x:0:
wheel:x:10:ben,anna
docker:x:980:ben
anna:x:1000:
ben:x:1001:
audio:x:63:anna
`

func TestParseAccounts(t *testing.T) {
	accounts := parseAccounts(testPasswd, testGroup)
	if len(accounts) != 2 {
		t.Fatalf("got %+v", accounts)
	}
	anna, ben := accounts[0], accounts[1]
	if anna.Name != "anna" || anna.UID != 1000 || !slices.Equal(anna.Groups, []string{"anna", "audio", "wheel"}) {
		t.Errorf("got %+v", anna)
	}
	if !slices.Equal(ben.Privileged, []string{"docker", "wheel"}) {
		t.Errorf("got %+v", ben)
	}
}

func TestParseSudoList(t *testing.T) {
	const listed = `Matching Defaults entries for anna on host:
    !visiblepw, always_set_home, env_reset

User anna may run the following commands on host:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/dnf
`
	got := parseSudoList(listed, nil)
	if got.unknown || !slices.Equal(got.rules, []string{"(ALL : ALL) ALL", "(root) NOPASSWD: /usr/bin/dnf"}) {
		t.Errorf("got %+v", got)
	}
	got = parseSudoList("User ben is not allowed to run sudo on host.\n", errors.New("exit status 1"))
	if got.unknown || len(got.rules) != 0 {
		t.Errorf("got %+v", got)
	}
	for _, out := range []string{"", "sudo: unable to resolve host\n"} {
		if got := parseSudoList(out, exec.ErrNotFound); !got.unknown {
			t.Errorf("%q: got %+v", out, got)
		}
	}
}

func writeFile(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAccountsReport(t *testing.T) {
	e, _ := newExecutor(t)
	writeFile(t, e.Root, "/etc/passwd", testPasswd)
	writeFile(t, e.Root, "/etc/group", testGroup)
	writeFile(t, e.Root, "/etc/sudoers", "")
	asked := 0
	e.Run = func(_ context.Context, name string, args ...string) (string, error) {
		asked++
		if name != "sudo" || args[len(args)-1] == "ben" {
			return "User ben is not allowed to run sudo on host.\n", errors.New("exit status 1")
		}
		return "User anna may run the following commands on host:\n    (ALL) ALL\n", nil
	}
	expires := time.Now().Add(time.Hour).UTC()
	if err := e.Grants.Set("anna", expires); err != nil {
		t.Fatal(err)
	}
	accounts := e.collectInsight(context.Background()).Accounts
	if len(accounts) != 2 || !slices.Equal(accounts[0].Sudo, []string{"(ALL) ALL"}) || accounts[1].Sudo != nil {
		t.Fatalf("got %+v", accounts)
	}
	if accounts[0].GrantExpires == nil || !accounts[0].GrantExpires.Equal(expires) || accounts[1].GrantExpires != nil {
		t.Errorf("got %+v", accounts)
	}

	// Every question lands in the system log, so a quiet system gets none.
	e.collectInsight(context.Background())
	if asked != 2 {
		t.Errorf("sudo asked %d times", asked)
	}
	writeFile(t, e.Root, "/etc/sudoers.d/hauswart-ben", "ben ALL=(ALL) ALL\n")
	e.collectInsight(context.Background())
	if asked != 4 {
		t.Errorf("a new rule must be noticed, sudo asked %d times", asked)
	}
}

func TestOddAccountNameStaysAwayFromSudo(t *testing.T) {
	e, _ := newExecutor(t)
	writeFile(t, e.Root, "/etc/passwd", "--help:x:1000:1000::/:/bin/sh\n")
	e.Run = func(context.Context, string, ...string) (string, error) {
		t.Error("sudo was called")
		return "", nil
	}
	if accounts := e.collectInsight(context.Background()).Accounts; len(accounts) != 1 || !accounts[0].SudoUnknown {
		t.Errorf("got %+v", accounts)
	}
}

func TestUpdateParsers(t *testing.T) {
	dnf := parseDnfUpgrades("Updating and loading repositories:\nbash.x86_64\nbash.x86_64\nglibc.i686\n\nRepositories loaded.\n")
	if !slices.Equal(dnf, []string{"bash.x86_64", "glibc.i686"}) {
		t.Errorf("dnf: %v", dnf)
	}
	apt := parseAptSimulation(`NOTE: This is only a simulation!
Reading package lists...
The following packages will be upgraded:
  tzdata
Inst tzdata [2025a-1] (2025b-1 Debian:13/stable [all])
Conf tzdata (2025b-1 Debian:13/stable [all])
`)
	if !slices.Equal(apt, []string{"tzdata"}) {
		t.Errorf("apt: %v", apt)
	}
	zypper := parseZypperUpdates(`<?xml version='1.0'?>
<stream>
<update-status version="0.6">
<update-list>
<update kind="package" name="openSUSE-build-key" edition="1.0-69.1" arch="x86_64" edition-old="1.0-68.1"><summary>x</summary></update>
<update name="other" kind="package" edition="2"><summary>y</summary></update>
<update kind="patch" name="openSUSE-2026-1" edition="1"></update>
</update-list>
</update-status>
</stream>`)
	if !slices.Equal(zypper, []string{"openSUSE-build-key", "other"}) {
		t.Errorf("zypper: %v", zypper)
	}
	pacman := parsePacmanUpgrades("warning: database file for 'core' does not exist\nexpat 2.9.0-1 -> 2.10.0-1\nlibnghttp2 1.70.0-1 -> 1.71.0-1\n")
	if !slices.Equal(pacman, []string{"expat", "libnghttp2"}) {
		t.Errorf("pacman: %v", pacman)
	}
}

func TestOstreeStatus(t *testing.T) {
	const pending = `{"deployments":[{"booted":false},{"booted":true}],
		"cached-update":{"rpm-diff":{"upgraded":[["bash",1,"a"],["vim",1,"b"]],"removed":[["x"]],"added":[["new",1,"c"]]}}}`
	names, err := parseOstreeUpdates(pending)
	if err != nil || !slices.Equal(names, []string{"bash", "vim", "new"}) {
		t.Errorf("got %v, %v", names, err)
	}
	if got := ostreeReboot(pending); got != api.RebootRequired {
		t.Errorf("got %s", got)
	}
	// As Fedora CoreOS 44 reports it.
	const image = `{"deployments":[{"booted":true}],"cached-update":{"checksum":"abc","version":"44.20261023.3.1",
		"manifest-diff":{"n-added":45,"n-removed":45,"removed-size":635373279,"total-size":938376209,"total":66,"added-size":641389006}}}`
	if names, err := parseOstreeUpdates(image); err != nil || !slices.Equal(names, []string{"44.20261023.3.1"}) {
		t.Errorf("got %v, %v", names, err)
	}
	const clean = `{"deployments":[{"booted":true}]}`
	if names, err := parseOstreeUpdates(clean); err != nil || len(names) != 0 {
		t.Errorf("got %v, %v", names, err)
	}
	if got := ostreeReboot(clean); got != api.RebootNotRequired {
		t.Errorf("got %s", got)
	}
	if got := ostreeReboot("nonsense"); got != api.RebootUnknown {
		t.Errorf("got %s", got)
	}
	if _, err := parseOstreeUpdates("nonsense"); err == nil {
		t.Error("broken status must fail")
	}
}

func TestEveryBackendHasAnUpdateCheck(t *testing.T) {
	for _, name := range []string{"dnf5", "dnf", "apt-get", "zypper", "pacman"} {
		backend := detectBackend(func(n string) bool { return n == name }, false)
		if _, ok := updateChecks[backend.Name]; !ok {
			t.Errorf("no check for %s", backend.Name)
		}
	}
	backend := detectBackend(func(n string) bool { return n == "rpm-ostree" }, true)
	if _, ok := updateChecks[backend.Name]; !ok {
		t.Errorf("no check for %s", backend.Name)
	}
}

func TestPacmanCheckLeavesTheRealDatabaseAlone(t *testing.T) {
	e, _ := newExecutor(t)
	e.Platform.Backend = detectBackend(func(n string) bool { return n == "pacman" }, false)
	var calls [][]string
	e.Run = func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, append([]string{name}, args...))
		if slices.Contains(args, "-Qu") {
			return "expat 1 -> 2\n", errors.New("exit status 1")
		}
		return "", nil
	}
	names, err := (e).pacmanCheck(context.Background())
	if err != nil || !slices.Equal(names, []string{"expat"}) {
		t.Fatalf("got %v, %v", names, err)
	}
	for _, call := range calls {
		if !slices.Contains(call, "--dbpath") {
			t.Errorf("call without its own database: %v", call)
		}
	}
	if _, err := e.pacmanCheck(context.Background()); err != nil {
		t.Errorf("second run: %v", err)
	}
}

func TestRebootState(t *testing.T) {
	const running = "6.1.0-test"
	dnfSays := func(text string) func(context.Context, string, ...string) (string, error) {
		return func(context.Context, string, ...string) (string, error) { return text, nil }
	}
	const required = "Core libraries or services have been updated since boot-up:\nReboot is required to fully utilize these updates.\n"
	const fine = "No core libraries or services have been updated since boot-up.\nReboot should not be necessary.\n"
	const missing = "No such command: needs-restarting.\n"
	for name, c := range map[string]struct {
		files map[string]string
		older string
		newer string
		hint  string
		want  string
	}{
		"package manager says so":  {hint: required, want: api.RebootRequired},
		"package manager says no":  {hint: fine, want: api.RebootNotRequired},
		"no answer in a container": {hint: missing, want: api.RebootUnknown},
		"debian marker":            {hint: missing, files: map[string]string{"/run/reboot-required": ""}, want: api.RebootRequired},
		"newest kernel running":    {hint: missing, older: running, newer: running, want: api.RebootNotRequired},
		"running kernel removed":   {hint: fine, older: "6.0.0", want: api.RebootRequired},
		"newer kernel installed":   {hint: fine, older: running, newer: "6.2.0", want: api.RebootRequired},
		"older kernel left over":   {hint: fine, older: "6.0.0", newer: running, want: api.RebootNotRequired},
	} {
		e, _ := newExecutor(t)
		e.Run = dnfSays(c.hint)
		writeFile(t, e.Root, "/proc/sys/kernel/osrelease", running+"\n")
		for path, content := range c.files {
			writeFile(t, e.Root, path, content)
		}
		base := time.Now().Add(-time.Hour)
		for i, version := range []string{c.older, c.newer} {
			if version == "" {
				continue
			}
			dir := filepath.Join(e.Root, "/usr/lib/modules", version)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			at := base.Add(time.Duration(i) * time.Minute)
			if err := os.Chtimes(dir, at, at); err != nil {
				t.Fatal(err)
			}
		}
		if got := e.rebootState(context.Background()); got != c.want {
			t.Errorf("%s: got %s, want %s", name, got, c.want)
		}
	}
}

func TestRebootTextOfZypper(t *testing.T) {
	const required = "Since the last system boot core libraries or services have been updated.\nReboot is suggested to ensure that your system benefits from these updates.\n"
	const fine = "No core libraries or services have been updated since the last system boot.\nReboot is probably not necessary.\n"
	e, _ := newExecutor(t)
	e.Platform.Backend = detectBackend(func(n string) bool { return n == "zypper" }, false)
	for text, want := range map[string]string{required: api.RebootRequired, fine: api.RebootNotRequired, "": api.RebootUnknown} {
		e.Run = func(context.Context, string, ...string) (string, error) { return text, nil }
		if got := e.rebootHint(context.Background()); got != want {
			t.Errorf("%q: got %s", text, got)
		}
	}
}

func TestFailedCheckKeepsTheLastResult(t *testing.T) {
	e, _ := newExecutor(t)
	output, failure := "bash.x86_64\n", error(nil)
	e.Run = func(_ context.Context, _ string, args ...string) (string, error) {
		if slices.Contains(args, "repoquery") {
			return output, failure
		}
		return "", nil
	}
	if err := e.checkUpdates(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := e.collectInsight(context.Background()).Updates
	if first.Pending != 1 || first.CheckedAt == nil || first.Error != "" {
		t.Fatalf("got %+v", first)
	}

	output, failure = "mirror\x1b is down", errors.New("exit status 1")
	if err := e.checkUpdates(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	second := e.collectInsight(context.Background()).Updates
	if second.Pending != 1 || !second.CheckedAt.Equal(*first.CheckedAt) || !strings.Contains(second.Error, "mirror  is down") {
		t.Errorf("got %+v", second)
	}

	output, failure = "", nil
	if err := e.checkUpdates(context.Background()); err != nil {
		t.Fatal(err)
	}
	if third := e.collectInsight(context.Background()).Updates; third.Pending != 0 || third.Error != "" {
		t.Errorf("got %+v", third)
	}
}

func TestManyUpdatesAreCountedButNotAllNamed(t *testing.T) {
	e, _ := newExecutor(t)
	var out strings.Builder
	for i := range api.MaxUpdateNames + 5 {
		fmt.Fprintf(&out, "pkg%d.x86_64\n", i)
	}
	e.Run = func(context.Context, string, ...string) (string, error) { return out.String(), nil }
	if err := e.checkUpdates(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := e.collectInsight(context.Background()).Updates
	if status.Pending != api.MaxUpdateNames+5 || len(status.Packages) != api.MaxUpdateNames {
		t.Errorf("pending %d, names %d", status.Pending, len(status.Packages))
	}
}

func TestNoPackageManager(t *testing.T) {
	e, _ := newExecutor(t)
	e.Platform.Backend = nil
	if err := e.checkUpdates(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	if status := e.collectInsight(context.Background()).Updates; status.Error == "" || status.Reboot != api.RebootUnknown {
		t.Errorf("got %+v", status)
	}
}

// A package manager refuses to run twice, so a check must wait for a task, and
// the task must make the result count as out of date.
func TestPackageTaskAndCheckTakeTurns(t *testing.T) {
	e, _ := newExecutor(t)
	release := make(chan struct{})
	started := make(chan struct{})
	checked := make(chan struct{})
	e.Run = func(_ context.Context, _ string, args ...string) (string, error) {
		if slices.Contains(args, "install") {
			close(started)
			<-release
		}
		return "", nil
	}
	go e.Execute(context.Background(), task(t, api.TaskPkgInstall, api.PackagesPayload{Packages: []string{"tree"}}))
	<-started
	go func() {
		e.checkUpdates(context.Background())
		close(checked)
	}()
	select {
	case <-checked:
		t.Fatal("check ran during a package task")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-checked
	if e.updateCheckDue() {
		t.Error("the check that waited already saw the result of the task")
	}
	e.Execute(context.Background(), task(t, api.TaskPkgUpgrade, struct{}{}))
	if !e.updateCheckDue() {
		t.Error("a package task must ask for a new check")
	}
}
