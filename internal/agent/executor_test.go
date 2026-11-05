package agent

import (
	"context"
	"crypto/x509"
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

type fakeRunner struct {
	calls  [][]string
	inputs []string
	err    error
}

func (f *fakeRunner) runInput(ctx context.Context, input, name string, args ...string) (string, error) {
	f.inputs = append(f.inputs, input)
	return f.run(ctx, name, args...)
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return "", f.err
}

func newExecutor(t *testing.T) (*Executor, *fakeRunner) {
	t.Helper()
	root := t.TempDir()
	grants, err := OpenGrants(filepath.Join(t.TempDir(), "grants.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	return &Executor{
		Root:         root,
		AllowedPaths: DefaultAllowedPaths,
		Grants:       grants,
		Run:          runner.run,
		RunInput:     runner.runInput,
		Platform:     Platform{Backend: detectBackend(func(n string) bool { return n == "dnf5" }, false)},
	}, runner
}

func task(t *testing.T, taskType string, payload any) api.Task {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return api.Task{ID: "t", Type: taskType, Payload: raw}
}

func currentUser(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if !api.ValidUser(u.Username) {
		t.Skip("test needs an ordinary account")
	}
	return u.Username
}

func TestFilePutOnlyInsideAllowedPaths(t *testing.T) {
	e, _ := newExecutor(t)
	ok := e.Execute(context.Background(), task(t, api.TaskFilePut, api.FilePutPayload{Path: "/etc/hauswart.d/app/a.conf", Content: "x"}))
	if !ok.OK {
		t.Fatalf("allowed path refused: %s", ok.Output)
	}
	for _, path := range []string{"/etc/sudoers.d/evil", "/etc/hauswart.dx/a", "/etc/shadow", "/usr/bin/sudo"} {
		res := e.Execute(context.Background(), task(t, api.TaskFilePut, api.FilePutPayload{Path: path, Content: "x"}))
		if res.OK {
			t.Errorf("wrote outside allowed paths: %s", path)
		}
		if _, err := os.Stat(filepath.Join(e.Root, path)); err == nil {
			t.Errorf("file exists: %s", path)
		}
	}
}

func TestFilePutDoesNotFollowSymlinks(t *testing.T) {
	e, _ := newExecutor(t)
	allowed := filepath.Join(e.Root, "etc/hauswart.d")
	secret := filepath.Join(e.Root, "etc/sudoers.d")
	for _, d := range []string{allowed, secret} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(secret, filepath.Join(allowed, "link")); err != nil {
		t.Fatal(err)
	}
	res := e.Execute(context.Background(), task(t, api.TaskFilePut, api.FilePutPayload{Path: "/etc/hauswart.d/link/evil", Content: "x"}))
	if res.OK {
		t.Fatal("wrote through a directory symlink")
	}
	target := filepath.Join(e.Root, "victim")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(allowed, "file")); err != nil {
		t.Fatal(err)
	}
	res = e.Execute(context.Background(), task(t, api.TaskFilePut, api.FilePutPayload{Path: "/etc/hauswart.d/file", Content: "new"}))
	if res.OK {
		t.Fatal("wrote through a file symlink")
	}
	if data, _ := os.ReadFile(target); string(data) != "old" {
		t.Fatal("symlink target was overwritten")
	}
}

func TestSudoGrantLifecycle(t *testing.T) {
	e, runner := newExecutor(t)
	name := currentUser(t)
	file := filepath.Join(e.Root, sudoersFile(name))

	res := e.Execute(context.Background(), task(t, api.TaskSudoGrant, api.SudoGrantPayload{User: name, ExpiresAt: time.Now().Add(time.Hour)}))
	if !res.OK {
		t.Fatal(res.Output)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), name+" ALL=(ALL:ALL) ALL") {
		t.Fatalf("unexpected rule: %s", data)
	}
	if info, _ := os.Stat(file); info.Mode().Perm() != 0o440 {
		t.Fatalf("mode %v", info.Mode())
	}
	if len(runner.calls) != 1 || runner.calls[0][0] != "visudo" {
		t.Fatalf("visudo not run: %v", runner.calls)
	}

	if err := e.RevokeExpired(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("unexpired grant was removed")
	}

	if err := e.Grants.Set(name, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := e.RevokeExpired(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expired grant still in place")
	}
}

func TestSudoGrantSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.json")
	g, err := OpenGrants(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Set("anna", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenGrants(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.Expired(time.Now()); len(got) != 1 || got[0] != "anna" {
		t.Fatalf("expiry lost across restart: %v", got)
	}
}

func TestSudoGrantRejectedByVisudoLeavesNoRule(t *testing.T) {
	e, runner := newExecutor(t)
	name := currentUser(t)
	runner.err = errors.New("syntax error")
	res := e.Execute(context.Background(), task(t, api.TaskSudoGrant, api.SudoGrantPayload{User: name, ExpiresAt: time.Now().Add(time.Hour)}))
	if res.OK {
		t.Fatal("grant reported success")
	}
	entries, _ := os.ReadDir(filepath.Join(e.Root, "etc/sudoers.d"))
	if len(entries) != 0 {
		t.Fatalf("left files behind: %v", entries)
	}
}

func TestUserPasswordKeepsHashOutOfArguments(t *testing.T) {
	e, runner := newExecutor(t)
	name := currentUser(t)
	hash := "$6$salt$" + strings.Repeat("a", 86)
	res := e.Execute(context.Background(), task(t, api.TaskUserPassword, api.PasswordPayload{User: name, Hash: hash}))
	if !res.OK {
		t.Fatal(res.Output)
	}
	if len(runner.inputs) != 1 || runner.inputs[0] != name+":"+hash+"\n" {
		t.Fatalf("stdin: %q", runner.inputs)
	}
	if len(runner.calls) != 2 || runner.calls[0][0] != "chpasswd" || runner.calls[1][0] != "chage" {
		t.Fatalf("calls: %v", runner.calls)
	}
	for _, call := range runner.calls {
		if strings.Contains(strings.Join(call, " "), hash) {
			t.Fatal("hash visible in the process list")
		}
	}
}

func TestUserPasswordRefusesSystemAccounts(t *testing.T) {
	e, runner := newExecutor(t)
	hash := "$6$salt$" + strings.Repeat("a", 86)
	res := e.Execute(context.Background(), task(t, api.TaskUserPassword, api.PasswordPayload{User: "daemon", Hash: hash}))
	if res.OK || len(runner.calls) != 0 {
		t.Fatalf("changed a system account: %v", runner.calls)
	}
}

func TestSudoGrantRefusesSystemAccounts(t *testing.T) {
	e, _ := newExecutor(t)
	res := e.Execute(context.Background(), task(t, api.TaskSudoGrant, api.SudoGrantPayload{User: "daemon", ExpiresAt: time.Now().Add(time.Hour)}))
	if res.OK {
		t.Fatal("granted sudo to a system account")
	}
	if _, err := os.Stat(filepath.Join(e.Root, sudoersFile("daemon"))); err == nil {
		t.Fatal("wrote a rule for a system account")
	}
}

func TestExpiredGrantRefused(t *testing.T) {
	e, _ := newExecutor(t)
	res := e.Execute(context.Background(), task(t, api.TaskSudoGrant, api.SudoGrantPayload{User: currentUser(t), ExpiresAt: time.Now().Add(-time.Minute)}))
	if res.OK {
		t.Fatal("expired grant accepted")
	}
}

func TestFlatpakAddsFlathubFirst(t *testing.T) {
	e, runner := newExecutor(t)
	e.Platform.Flatpak = true
	res := e.Execute(context.Background(), task(t, api.TaskFlatpakInstall, api.PackagesPayload{Packages: []string{"org.example.App"}}))
	if !res.OK {
		t.Fatal(res.Output)
	}
	if len(runner.calls) != 2 || runner.calls[0][1] != "remote-add" || runner.calls[1][1] != "install" {
		t.Fatalf("calls: %v", runner.calls)
	}
}

func TestExecutorValidatesIndependently(t *testing.T) {
	e, runner := newExecutor(t)
	res := e.Execute(context.Background(), api.Task{Type: api.TaskPkgInstall, Payload: json.RawMessage(`{"packages":["--evil"]}`)})
	if res.OK || len(runner.calls) != 0 {
		t.Fatalf("malicious task reached the package manager: %v", runner.calls)
	}
	res = e.Execute(context.Background(), api.Task{Type: "shell.exec", Payload: json.RawMessage(`{"cmd":"id"}`)})
	if res.OK {
		t.Fatal("unknown task type accepted")
	}
}

func TestDetectBackendPrefersRpmOstreeOnAtomic(t *testing.T) {
	has := func(n string) bool { return n == "rpm-ostree" || n == "dnf5" }
	if b := detectBackend(has, true); b.Name != "rpm-ostree" {
		t.Fatalf("got %s", b.Name)
	}
	if b := detectBackend(has, false); b.Name != "dnf5" {
		t.Fatalf("got %s", b.Name)
	}
}

func TestDetectTrustUsesTheDistroLayout(t *testing.T) {
	cases := []struct {
		name     string
		commands []string
		dirs     []string
		want     string
	}{
		{"fedora", []string{"update-ca-trust", "trust"}, []string{"/etc/pki/ca-trust/source"}, "/etc/pki/ca-trust/source/anchors"},
		{"arch", []string{"update-ca-trust", "trust"}, []string{"/etc/ca-certificates/trust-source"}, "/etc/ca-certificates/trust-source/anchors"},
		{"opensuse", []string{"update-ca-certificates"}, []string{"/etc/pki/trust/anchors"}, "/etc/pki/trust/anchors"},
		{"debian", []string{"update-ca-certificates"}, nil, "/usr/local/share/ca-certificates"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			has := func(n string) bool { return slices.Contains(c.commands, n) }
			dirExists := func(p string) bool { return slices.Contains(c.dirs, p) }
			got := detectTrust(has, dirExists)
			if got == nil || got.Dir != c.want {
				t.Fatalf("got %+v, want %s", got, c.want)
			}
		})
	}
}

func TestRenewDue(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{NotBefore: start, NotAfter: start.Add(300 * 24 * time.Hour)}
	cases := []struct {
		day  int
		want bool
	}{{0, false}, {100, false}, {199, false}, {201, true}, {299, true}, {400, true}}
	for _, c := range cases {
		if got := renewDue(leaf, start.Add(time.Duration(c.day)*24*time.Hour)); got != c.want {
			t.Errorf("day %d: got %v", c.day, got)
		}
	}
}

func TestRenewInterval(t *testing.T) {
	start := time.Now()
	long := &x509.Certificate{NotBefore: start, NotAfter: start.Add(2 * 365 * 24 * time.Hour)}
	if got := renewInterval(long); got != maxRenewInterval {
		t.Errorf("long lifetime: %v", got)
	}
	short := &x509.Certificate{NotBefore: start, NotAfter: start.Add(5 * time.Second)}
	if got := renewInterval(short); got != minRenewInterval {
		t.Errorf("short lifetime: %v", got)
	}
}

func TestParseMeminfo(t *testing.T) {
	total, used := parseMeminfo([]byte("MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 400 kB\n"))
	if total != 1000*1024 || used != 600*1024 {
		t.Fatalf("total %d used %d", total, used)
	}
}
