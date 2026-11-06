package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/philippe/hauswart/internal/api"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const testPEM = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n"

// fakeSystem answers like a device with some packages on it.
type fakeSystem struct {
	calls    [][]string
	packages map[string]bool
	failed   map[string]bool // install fails for these
	flatpaks []string
	noChange bool
	upgrades string
}

func (f *fakeSystem) run(_ context.Context, name string, args ...string) (string, error) {
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)
	switch {
	case name == "rpm":
		if f.packages[args[len(args)-1]] {
			return "", nil
		}
		return "", errors.New("exit status 1")
	case name == "dnf5" && args[0] == "install":
		names := args[2:]
		for _, pkg := range names {
			if f.failed[pkg] {
				return "No match for " + pkg, errors.New("exit status 1")
			}
		}
		if !f.noChange {
			for _, pkg := range names {
				f.packages[pkg] = true
			}
		}
	case name == "dnf5" && args[0] == "remove":
		for _, pkg := range args[2:] {
			delete(f.packages, pkg)
		}
	case name == "flatpak" && args[0] == "list":
		return strings.Join(f.flatpaks, "\n"), nil
	case name == "flatpak" && args[0] == "uninstall":
		for _, app := range args[5:] {
			f.flatpaks = slices.DeleteFunc(f.flatpaks, func(have string) bool { return have == app })
		}
	case name == "flatpak" && args[0] == "install":
		f.flatpaks = append(f.flatpaks, args[len(args)-1])
	}
	return "", nil
}

func newEngine(t *testing.T) (*PolicyEngine, *fakeSystem) {
	t.Helper()
	e, _ := newExecutor(t)
	system := &fakeSystem{packages: map[string]bool{}, failed: map[string]bool{}}
	e.Run = system.run
	e.Platform.Trust = &Trust{Dir: "/anchors", Update: []string{"update-ca-trust", "extract"}}
	return OpenPolicy(t.TempDir(), e, quiet()), system
}

func deviationItems(status *api.PolicyStatus) []string {
	var items []string
	for _, d := range status.Deviations {
		items = append(items, d.Kind+" "+d.Item)
	}
	return items
}

func setPolicy(t *testing.T, pe *PolicyEngine, p api.Policy) {
	t.Helper()
	if err := pe.Set(p); err != nil {
		t.Fatal(err)
	}
}

func TestEnforceInstallsAndRemoves(t *testing.T) {
	pe, system := newEngine(t)
	system.packages["steam"] = true
	system.packages["git"] = true
	setPolicy(t, pe, api.Policy{RequiredPackages: []string{"vim", "git"}, ForbiddenPackages: []string{"steam"}})
	pe.Enforce(context.Background())

	if !system.packages["vim"] || system.packages["steam"] {
		t.Fatalf("got %v", system.packages)
	}
	status := pe.Status()
	if len(status.Deviations) != 0 || !slices.Equal(status.Corrected, []string{"package steam", "package vim"}) {
		t.Fatalf("got %+v", status)
	}

	system.calls = nil
	pe.Enforce(context.Background())
	if slices.ContainsFunc(system.calls, func(c []string) bool { return c[0] == "dnf5" }) {
		t.Fatalf("touched a device that was fine: %v", system.calls)
	}
	if pe.Status().Corrected != nil {
		t.Fatal("reported a correction that did not happen")
	}
}

func TestOneBadPackageCostsOnlyThatPackage(t *testing.T) {
	pe, system := newEngine(t)
	system.failed["nonsense"] = true
	setPolicy(t, pe, api.Policy{RequiredPackages: []string{"nonsense", "vim"}})
	pe.Enforce(context.Background())
	if !system.packages["vim"] {
		t.Fatal("a bad name stopped a good one")
	}
	status := pe.Status()
	if !slices.Equal(deviationItems(status), []string{"package nonsense"}) || !strings.Contains(status.Deviations[0].Detail, "No match") {
		t.Fatalf("got %+v", status)
	}
}

// Success from a package manager proves nothing, as with a virtual name.
func TestSuccessWithoutEffectIsADeviation(t *testing.T) {
	pe, system := newEngine(t)
	system.noChange = true
	setPolicy(t, pe, api.Policy{RequiredPackages: []string{"vim"}})
	pe.Enforce(context.Background())
	if status := pe.Status(); len(status.Deviations) != 1 || status.Deviations[0].Detail != "still not installed" {
		t.Fatalf("got %+v", status)
	}
}

func TestFilesAreRestoredAndBoundToTheAllowedPaths(t *testing.T) {
	pe, _ := newEngine(t)
	allowed := api.FilePutPayload{Path: "/etc/hauswart.d/motd", Content: "hello", Mode: "0640"}
	outside := api.FilePutPayload{Path: "/etc/cron.d/evil", Content: "x"}
	setPolicy(t, pe, api.Policy{Files: []api.FilePutPayload{allowed, outside}})
	pe.Enforce(context.Background())

	full := pe.exec.path(allowed.Path)
	if raw, err := os.ReadFile(full); err != nil || string(raw) != "hello" {
		t.Fatalf("%q, %v", raw, err)
	}
	if _, err := os.Stat(pe.exec.path(outside.Path)); err == nil {
		t.Fatal("a policy wrote outside the allowed paths")
	}
	if got := deviationItems(pe.Status()); !slices.Equal(got, []string{"file /etc/cron.d/evil"}) {
		t.Fatalf("got %v", got)
	}

	if err := os.WriteFile(full, []byte("changed"), 0o640); err != nil {
		t.Fatal(err)
	}
	pe.Enforce(context.Background())
	if raw, _ := os.ReadFile(full); string(raw) != "hello" {
		t.Fatalf("got %q", raw)
	}
	if err := os.Chmod(full, 0o666); err != nil {
		t.Fatal(err)
	}
	pe.Enforce(context.Background())
	if info, _ := os.Stat(full); info.Mode().Perm() != 0o640 {
		t.Fatalf("got %v", info.Mode())
	}
}

func TestSymlinkIsNotFollowedByAPolicy(t *testing.T) {
	pe, _ := newEngine(t)
	file := api.FilePutPayload{Path: "/etc/hauswart.d/link", Content: "x"}
	full := pe.exec.path(file.Path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, full); err != nil {
		t.Fatal(err)
	}
	setPolicy(t, pe, api.Policy{Files: []api.FilePutPayload{file}})
	pe.Enforce(context.Background())
	if got := deviationItems(pe.Status()); !slices.Equal(got, []string{"file /etc/hauswart.d/link"}) {
		t.Fatalf("got %v", got)
	}
}

func installFakeCA(t *testing.T, pe *PolicyEngine) {
	t.Helper()
	// caInstall parses the certificate, so the file is put in place directly
	// and only removal and the bookkeeping are under test here.
	path := pe.exec.caPath("home")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(testPEM), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCALeavesTheStoreWithThePolicy(t *testing.T) {
	pe, system := newEngine(t)
	installFakeCA(t, pe)
	setPolicy(t, pe, api.Policy{CAs: []api.CAInstallPayload{{Name: "home", PEM: testPEM}}})
	pe.Enforce(context.Background())
	if !slices.Equal(pe.state.ManagedCAs, []string{"home"}) {
		t.Fatalf("got %v", pe.state.ManagedCAs)
	}

	// The state survives a restart, or a CA would stay trusted forever.
	reopened := OpenPolicy(pe.dir, pe.exec, quiet())
	if err := reopened.Clear(); err != nil {
		t.Fatal(err)
	}
	reopened.Enforce(context.Background())
	if _, err := os.Stat(pe.exec.caPath("home")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the CA is still trusted")
	}
	if !slices.ContainsFunc(system.calls, func(c []string) bool { return c[0] == "update-ca-trust" }) {
		t.Fatal("the trust store was not rebuilt")
	}
	if reopened.Status() != nil {
		t.Fatal("a device without a policy reports one")
	}
}

func TestCANotInstalledByAPolicyStays(t *testing.T) {
	pe, _ := newEngine(t)
	installFakeCA(t, pe)
	setPolicy(t, pe, api.Policy{RequiredPackages: []string{"vim"}})
	pe.Enforce(context.Background())
	if _, err := os.Stat(pe.exec.caPath("home")); err != nil {
		t.Fatal("removed a CA that the policy never managed")
	}
}

func TestBrokenPolicyKeepsWhatIsThere(t *testing.T) {
	pe, _ := newEngine(t)
	installFakeCA(t, pe)
	setPolicy(t, pe, api.Policy{CAs: []api.CAInstallPayload{{Name: "home", PEM: testPEM}}})
	pe.Enforce(context.Background())

	if err := os.WriteFile(filepath.Join(pe.dir, policyFile), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened := OpenPolicy(pe.dir, pe.exec, quiet())
	reopened.Enforce(context.Background())
	if _, err := os.Stat(pe.exec.caPath("home")); err != nil {
		t.Fatal("an unreadable policy removed a CA")
	}
	if got := deviationItems(reopened.Status()); !slices.Equal(got, []string{"policy policy.json"}) {
		t.Fatalf("got %v", got)
	}
}

func TestPolicySurvivesARestart(t *testing.T) {
	pe, _ := newEngine(t)
	p := api.Policy{RequiredPackages: []string{"vim"}}
	setPolicy(t, pe, p)
	reopened := OpenPolicy(pe.dir, pe.exec, quiet())
	if got := reopened.Status(); got == nil || got.Hash != p.Hash() {
		t.Fatalf("got %+v", got)
	}
}

func TestFlatpaks(t *testing.T) {
	pe, system := newEngine(t)
	pe.exec.Platform.Flatpak = true
	system.flatpaks = []string{"com.valvesoftware.Steam"}
	setPolicy(t, pe, api.Policy{RequiredFlatpaks: []string{"org.gnome.Calculator"}, ForbiddenFlatpaks: []string{"com.valvesoftware.Steam"}})
	pe.Enforce(context.Background())
	if !slices.Equal(system.flatpaks, []string{"org.gnome.Calculator"}) {
		t.Fatalf("got %v", system.flatpaks)
	}
	if status := pe.Status(); len(status.Deviations) != 0 {
		t.Fatalf("got %+v", status)
	}
}

func updatePolicy(reboot string) api.Policy {
	return api.Policy{
		TimeZone: "UTC",
		Updates:  &api.UpdateRule{Window: api.Window{Days: []string{"sat"}, Start: "02:00", End: "04:00"}, Reboot: reboot},
	}
}

func countCalls(calls [][]string, name string) int {
	n := 0
	for _, call := range calls {
		if strings.Join(call, " ") == name {
			n++
		}
	}
	return n
}

// 2026-11-07 is a Saturday.
var inWindow = time.Date(2026, 11, 7, 2, 30, 0, 0, time.UTC)

func withPendingUpdates(pe *PolicyEngine) {
	updateChecks["fake"] = func(*Executor, context.Context) ([]string, error) { return []string{"vim"}, nil }
	pe.exec.Platform.Backend.Name = "fake"
}

func TestUpdatesRunOncePerWindow(t *testing.T) {
	pe, system := newEngine(t)
	withPendingUpdates(pe)
	setPolicy(t, pe, updatePolicy(api.RebootNever))

	pe.runUpdates(context.Background(), inWindow.Add(-time.Hour)) // before the window
	if countCalls(system.calls, "dnf5 upgrade -y") != 0 {
		t.Fatal("ran outside the window")
	}
	pe.runUpdates(context.Background(), inWindow)
	pe.runUpdates(context.Background(), inWindow.Add(time.Minute))
	if got := countCalls(system.calls, "dnf5 upgrade -y"); got != 1 {
		t.Fatalf("ran %d times", got)
	}

	// A restart in the window does not start it again.
	reopened := OpenPolicy(pe.dir, pe.exec, quiet())
	reopened.runUpdates(context.Background(), inWindow.Add(2*time.Minute))
	if got := countCalls(system.calls, "dnf5 upgrade -y"); got != 1 {
		t.Fatalf("ran %d times after a restart", got)
	}

	next := inWindow.Add(7 * 24 * time.Hour)
	reopened.runUpdates(context.Background(), next)
	if got := countCalls(system.calls, "dnf5 upgrade -y"); got != 2 {
		t.Fatalf("the next window ran %d times in total", got)
	}
}

func TestWindowUsesThePolicyZone(t *testing.T) {
	pe, system := newEngine(t)
	withPendingUpdates(pe)
	p := updatePolicy(api.RebootNever)
	p.TimeZone = "Asia/Tokyo" // 02:30 UTC is 11:30 there
	setPolicy(t, pe, p)
	pe.runUpdates(context.Background(), inWindow)
	if countCalls(system.calls, "dnf5 upgrade -y") != 0 {
		t.Fatal("used the wrong zone")
	}
}

func TestRebootFollowsTheRule(t *testing.T) {
	for reboot, want := range map[string]int{api.RebootNever: 0, api.RebootWindow: 1} {
		pe, system := newEngine(t)
		withPendingUpdates(pe)
		if err := os.MkdirAll(pe.exec.path("/run"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pe.exec.path("/run/reboot-required"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		setPolicy(t, pe, updatePolicy(reboot))
		pe.runUpdates(context.Background(), inWindow)
		got := 0
		for _, call := range system.calls {
			if call[0] == "shutdown" && call[1] == "-r" && call[2] == "+10" {
				got++
			}
		}
		if got != want {
			t.Errorf("%s: %d reboots: %v", reboot, got, system.calls)
		}
	}
}

func TestFailedUpdateIsReported(t *testing.T) {
	pe, _ := newEngine(t)
	updateChecks["broken"] = func(*Executor, context.Context) ([]string, error) { return nil, errors.New("no network") }
	pe.exec.Platform.Backend.Name = "broken"
	setPolicy(t, pe, updatePolicy(api.RebootNever))
	pe.runUpdates(context.Background(), inWindow)
	if got := deviationItems(pe.Status()); !slices.Equal(got, []string{"updates automatic updates"}) {
		t.Fatalf("got %v", got)
	}
}

func TestUnprotectedDeviceRefusesPolicies(t *testing.T) {
	pe, _ := newEngine(t)
	a := &Agent{policy: pe, log: quiet()}
	result := a.handle(context.Background(), task(t, api.TaskPolicySet, api.Policy{RequiredPackages: []string{"vim"}}))
	if result.OK || !strings.Contains(result.Output, "pinned signing keys") {
		t.Fatalf("got %+v", result)
	}
	if pe.Status() != nil {
		t.Fatal("stored a policy")
	}
}

func TestBackendQueries(t *testing.T) {
	apt := detectBackend(func(n string) bool { return n == "apt-get" }, false)
	if apt.Present("config-files", nil) {
		t.Error("a removed Debian package counts as installed")
	}
	if !apt.Present("installed", nil) {
		t.Error("an installed Debian package counts as missing")
	}
	if detectBackend(func(n string) bool { return n == "pacman" }, false).Query("vim")[0] != "pacman" {
		t.Error("Arch has no rpm")
	}
	if detectBackend(func(n string) bool { return n == "rpm-ostree" }, true).Query("vim")[0] != "rpm" {
		t.Error("rpm-ostree systems answer through rpm")
	}
}

func TestHalfInstalledCAIsTriedAgain(t *testing.T) {
	pe, _ := newEngine(t)
	cert := testCert(t)
	fail := true
	pe.exec.Run = func(context.Context, string, ...string) (string, error) {
		if fail {
			return "", errors.New("exit status 1")
		}
		return "", nil
	}
	setPolicy(t, pe, api.Policy{CAs: []api.CAInstallPayload{{Name: "home", PEM: cert}}})
	pe.Enforce(context.Background())
	if got := deviationItems(pe.Status()); !slices.Equal(got, []string{"ca home"}) {
		t.Fatalf("got %v", got)
	}
	pe.Enforce(context.Background())
	if got := deviationItems(pe.Status()); !slices.Equal(got, []string{"ca home"}) {
		t.Fatalf("a failed install turned into success: %v", got)
	}
	fail = false
	pe.Enforce(context.Background())
	if status := pe.Status(); len(status.Deviations) != 0 || !slices.Contains(status.Corrected, "ca home") {
		t.Fatalf("got %+v", status)
	}
}

func TestUnreadableStateStopsEnforcement(t *testing.T) {
	pe, system := newEngine(t)
	setPolicy(t, pe, api.Policy{RequiredPackages: []string{"vim"}})
	if err := os.WriteFile(filepath.Join(pe.dir, policyStateFile), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened := OpenPolicy(pe.dir, pe.exec, quiet())
	reopened.Enforce(context.Background())
	if len(system.calls) != 0 {
		t.Fatalf("went on without knowing its CAs: %v", system.calls)
	}
	raw, _ := os.ReadFile(filepath.Join(pe.dir, policyStateFile))
	if string(raw) != "{broken" {
		t.Fatal("overwrote the state")
	}
	if status := reopened.Status(); len(status.Deviations) != 1 {
		t.Fatalf("got %+v", status)
	}
}

// A process that keeps the pipe open must not stop the agent, as a stopped
// helper in a user's session could.
func TestCommandsReturnEvenIfAChildHoldsThePipe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	RunCommand(ctx, "sh", "-c", "sleep 60 & wait")
	if took := time.Since(start); took > commandWaitDelay+3*time.Second {
		t.Fatalf("took %s", took)
	}
}
