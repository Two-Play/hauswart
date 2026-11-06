package agent

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Two-Play/hauswart/internal/api"
)

func appsEngine(t *testing.T) (*PolicyEngine, *directorySystem) {
	t.Helper()
	pe, system := newDirectoryEngine(t)
	pe.exec.Has = func(name string) bool { return name == "fagenrules" }
	base := pe.exec.Run
	pe.exec.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "getent" {
			return args[1] + ":x:2007:2007::/home/x:/bin/bash\n", nil
		}
		if name == "systemctl" && args[0] == "is-enabled" {
			return "", errors.New("exit status 1")
		}
		return base(ctx, name, args...)
	}
	return pe, system
}

func addProgram(t *testing.T, e *Executor, name string) {
	t.Helper()
	full := e.path("/usr/bin/" + name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, nil, 0o755); err != nil {
		t.Fatal(err)
	}
}

func addLauncher(t *testing.T, e *Executor, id, text string) {
	t.Helper()
	full := e.path(launcherDirs[0] + "/" + id + ".desktop")
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func rulesOf(t *testing.T, pe *PolicyEngine) string {
	t.Helper()
	raw, err := os.ReadFile(pe.exec.path(fapolicydOurRules))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestDownloadsAreBlockedForOnePerson(t *testing.T) {
	pe, _ := appsEngine(t)
	addProgram(t, pe.exec, "bash")
	setPolicy(t, pe, api.Policy{Apps: []api.AppRule{{User: "mia", BlockDownloads: true}}})
	pe.Enforce(context.Background())
	rules := rulesOf(t, pe)
	for _, want := range []string{
		"deny_audit perm=any uid=2007 pattern=ld_so : all",
		"deny_audit perm=execute uid=2007 : dir=/home/",
		"deny_audit perm=execute uid=2007 : dir=/tmp/",
		"exe=/usr/bin/bash : dir=/home/ ftype=text/x-shellscript",
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("no %q in\n%s", want, rules)
		}
	}
	raw, _ := os.ReadFile(pe.exec.path(fapolicydAllowAll))
	if !strings.Contains(string(raw), "allow perm=any all : all") {
		t.Fatalf("got %s", raw)
	}
}

// A mistake here must not reach the system: an ID below 1000 is no person.
func TestSystemAccountsGetNoRules(t *testing.T) {
	pe, _ := appsEngine(t)
	base := pe.exec.Run
	pe.exec.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "getent" {
			return args[1] + ":x:999:999::/:/sbin/nologin\n", nil
		}
		return base(ctx, name, args...)
	}
	setPolicy(t, pe, api.Policy{Apps: []api.AppRule{{User: "mia", BlockDownloads: true}}})
	pe.Enforce(context.Background())
	if _, err := os.Stat(pe.exec.path(fapolicydOurRules)); err == nil {
		t.Fatal("wrote rules for a system account")
	}
}

func TestUnknownUserIsReported(t *testing.T) {
	pe, _ := appsEngine(t)
	base := pe.exec.Run
	pe.exec.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "getent" {
			return "", errors.New("exit status 2")
		}
		return base(ctx, name, args...)
	}
	setPolicy(t, pe, api.Policy{Apps: []api.AppRule{{User: "nobody2", BlockDownloads: true}}})
	pe.Enforce(context.Background())
	if got := deviationItems(pe.Status()); !slices.Contains(got, "apps nobody2") {
		t.Fatalf("got %v", got)
	}
}

func TestForbiddenProgramFollowsLinks(t *testing.T) {
	pe, _ := appsEngine(t)
	addProgram(t, pe.exec, "real-game")
	if err := os.Symlink("real-game", pe.exec.path("/usr/bin/game")); err != nil {
		t.Fatal(err)
	}
	setPolicy(t, pe, api.Policy{Apps: []api.AppRule{{User: "mia", ForbiddenPrograms: []string{"/usr/bin/game"}}}})
	pe.Enforce(context.Background())
	if rules := rulesOf(t, pe); !strings.Contains(rules, "path=/usr/bin/real-game\n") {
		t.Fatalf("got %s", rules)
	}
}

func TestLaunchers(t *testing.T) {
	cases := map[string]struct {
		text string
		ok   bool
		exec string
	}{
		"plain":      {"[Desktop Entry]\nType=Application\nName=Kate\nExec=kate %U\n", true, "kate"},
		"with env":   {"[Desktop Entry]\nType=Application\nName=X\nExec=env A=1 B=2 /usr/bin/x\n", true, "/usr/bin/x"},
		"quoted":     {"[Desktop Entry]\nType=Application\nName=X\nExec=\"/usr/bin/x\" --y\n", true, "/usr/bin/x"},
		"hidden":     {"[Desktop Entry]\nType=Application\nName=X\nExec=x\nNoDisplay=true\n", false, ""},
		"link":       {"[Desktop Entry]\nType=Link\nName=X\nExec=x\n", false, ""},
		"action":     {"[Desktop Entry]\nType=Application\nName=X\nExec=x\n[Desktop Action new]\nExec=other\nName=Y\n", true, "x"},
		"no program": {"[Desktop Entry]\nType=Application\nName=X\n", false, ""},
	}
	for name, c := range cases {
		_, exec, ok := parseLauncher(c.text)
		if ok != c.ok || (ok && execProgram(exec) != c.exec) {
			t.Errorf("%s: %q %v", name, exec, ok)
		}
	}
}

func TestStrictRuleBlocksWhatIsNotListed(t *testing.T) {
	pe, _ := appsEngine(t)
	for _, program := range []string{"kate", "steam", "plasmashell", "kcalc"} {
		addProgram(t, pe.exec, program)
	}
	addLauncher(t, pe.exec, "org.kde.kate", "[Desktop Entry]\nType=Application\nName=Kate\nExec=kate %U\n")
	addLauncher(t, pe.exec, "steam", "[Desktop Entry]\nType=Application\nName=Steam\nExec=/usr/bin/steam\n")
	addLauncher(t, pe.exec, "org.kde.plasmashell", "[Desktop Entry]\nType=Application\nName=Plasma\nExec=plasmashell\n")
	setPolicy(t, pe, api.Policy{Apps: []api.AppRule{{User: "mia", Strict: true, AllowedApps: []string{"org.kde.kate"}}}})
	pe.Enforce(context.Background())
	rules := rulesOf(t, pe)
	if !strings.Contains(rules, "path=/usr/bin/steam") {
		t.Fatalf("got %s", rules)
	}
	if strings.Contains(rules, "path=/usr/bin/kate") || strings.Contains(rules, "plasmashell") {
		t.Fatalf("blocked too much: %s", rules)
	}
	if !strings.Contains(rules, "dir=/home/") {
		t.Fatal("a strict rule has to block downloads as well")
	}

	// A new application is out until someone allows it.
	addLauncher(t, pe.exec, "org.kde.kcalc", "[Desktop Entry]\nType=Application\nName=Calc\nExec=kcalc\n")
	pe.Enforce(context.Background())
	if !strings.Contains(rulesOf(t, pe), "path=/usr/bin/kcalc") {
		t.Fatal("a new application got through")
	}
}

func TestApplicationsReachTheDashboard(t *testing.T) {
	pe, _ := appsEngine(t)
	addProgram(t, pe.exec, "kate")
	addLauncher(t, pe.exec, "org.kde.kate", "[Desktop Entry]\nType=Application\nName=Kate\nExec=kate\n")
	setPolicy(t, pe, api.Policy{RequiredPackages: nil, Language: "de"})
	pe.Enforce(context.Background())
	if apps := pe.Apps(); len(apps) != 1 || apps[0].ID != "org.kde.kate" || apps[0].Name != "Kate" {
		t.Fatalf("got %+v", apps)
	}
}

func TestShippedRulesComeBack(t *testing.T) {
	pe, system := appsEngine(t)
	shipped := pe.exec.path(fapolicydRulesDir + "/30-patterns.rules")
	if err := os.MkdirAll(filepath.Dir(shipped), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shipped, []byte("shipped"), 0o644); err != nil {
		t.Fatal(err)
	}
	setPolicy(t, pe, api.Policy{Apps: []api.AppRule{{User: "mia", BlockDownloads: true}}})
	pe.Enforce(context.Background())
	if _, err := os.Stat(shipped); err == nil {
		t.Fatal("rules for everyone are still in place")
	}
	if called(system.calls, "fagenrules --load") != 1 || called(system.calls, "systemctl restart fapolicyd") != 1 {
		t.Fatalf("got %v", system.calls)
	}
	if err := pe.Clear(); err != nil {
		t.Fatal(err)
	}
	pe.Enforce(context.Background())
	if raw, err := os.ReadFile(shipped); err != nil || string(raw) != "shipped" {
		t.Fatalf("%q %v", raw, err)
	}
	if called(system.calls, "systemctl disable --now fapolicyd") != 1 {
		t.Fatalf("got %v", system.calls)
	}
}

func TestOlderFapolicydHasOneFile(t *testing.T) {
	pe, _ := appsEngine(t)
	pe.exec.Has = func(string) bool { return false }
	full := pe.exec.path(fapolicydOneFile)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("shipped"), 0o644); err != nil {
		t.Fatal(err)
	}
	setPolicy(t, pe, api.Policy{Apps: []api.AppRule{{User: "mia", BlockDownloads: true}}})
	pe.Enforce(context.Background())
	raw, _ := os.ReadFile(full)
	if !strings.Contains(string(raw), "uid=2007") || !strings.HasSuffix(string(raw), "allow perm=any all : all\n") {
		t.Fatalf("got %s", raw)
	}
	if err := pe.Clear(); err != nil {
		t.Fatal(err)
	}
	pe.Enforce(context.Background())
	if raw, _ := os.ReadFile(full); string(raw) != "shipped" {
		t.Fatalf("got %s", raw)
	}
}

func TestStoppedServiceIsStartedAgain(t *testing.T) {
	pe, system := appsEngine(t)
	setPolicy(t, pe, api.Policy{Apps: []api.AppRule{{User: "mia", BlockDownloads: true}}})
	pe.Enforce(context.Background())
	base := pe.exec.Run
	stopped := true
	pe.exec.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "systemctl" && args[0] == "is-active" && args[len(args)-1] == "fapolicyd" && stopped {
			return "", errors.New("exit status 3")
		}
		return base(ctx, name, args...)
	}
	system.calls = nil
	pe.Enforce(context.Background())
	if called(system.calls, "systemctl enable --now fapolicyd") != 1 || !slices.Contains(pe.Status().Corrected, "fapolicyd was not running") {
		t.Fatalf("got %v", system.calls)
	}
}

func TestFlatpakFilter(t *testing.T) {
	pe, system := appsEngine(t)
	setPolicy(t, pe, api.Policy{Apps: []api.AppRule{{User: "mia", Flatpaks: &api.FlatpakList{Mode: api.FlatpakAllow, Apps: []string{"org.gnome.Calculator"}}}}})
	pe.Enforce(context.Background())
	want := "busctl --system set-property org.freedesktop.Accounts /org/freedesktop/Accounts/User2007 com.endlessm.ParentalControls.AppFilter AppFilter (bas) true 1 app/org.gnome.Calculator/" + flatpakArch() + "/stable"
	if called(system.calls, want) != 1 {
		t.Fatalf("got %v", system.calls)
	}
	if called(system.calls, "busctl --system set-property org.freedesktop.Accounts /org/freedesktop/Accounts/User2007 com.endlessm.ParentalControls.AppFilter AllowUserInstallation b false") != 1 {
		t.Fatalf("got %v", system.calls)
	}
	if !system.packages["malcontent"] {
		t.Fatalf("got %v", system.packages)
	}

	// The rule goes, the filter goes, also after a restart.
	reopened := OpenPolicy(pe.dir, pe.exec, quiet())
	if err := reopened.Clear(); err != nil {
		t.Fatal(err)
	}
	reopened.Enforce(context.Background())
	if called(system.calls, "busctl --system set-property org.freedesktop.Accounts /org/freedesktop/Accounts/User2007 com.endlessm.ParentalControls.AppFilter AppFilter (bas) false 0") != 1 {
		t.Fatalf("got %v", system.calls)
	}
}

func TestStrictMeansAllowListForFlatpaks(t *testing.T) {
	if _, allow, _ := wantedFilter(api.AppRule{Strict: true, Flatpaks: &api.FlatpakList{Mode: api.FlatpakAllow, Apps: []string{"a"}}}); !allow {
		t.Fatal("a strict rule turned into a list of what is denied")
	}
	if limited, allow, apps := wantedFilter(api.AppRule{Strict: true}); !limited || !allow || len(apps) != 0 {
		t.Fatal("a strict rule left Flatpaks open")
	}
	if limited, _, _ := wantedFilter(api.AppRule{BlockDownloads: true}); limited {
		t.Fatal("limited Flatpaks nobody asked about")
	}
}

// The target of a link is up to whoever owns the link, and a name can hold a line
// break. Neither may become a rule.
func TestPathsFromTheFileSystemCannotAddRules(t *testing.T) {
	pe, _ := appsEngine(t)
	evil := "x\ndeny_audit perm=any all : all\n#"
	dir := pe.exec.path("/opt/game")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, evil), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	addProgram(t, pe.exec, "placeholder")
	if err := os.Symlink(filepath.Join(dir, evil), pe.exec.path("/usr/bin/game")); err != nil {
		t.Fatal(err)
	}
	addLauncher(t, pe.exec, "evil", "[Desktop Entry]\nType=Application\nName=Evil\nExec=/usr/bin/game\n")
	setPolicy(t, pe, api.Policy{Apps: []api.AppRule{{User: "mia", Strict: true, ForbiddenPrograms: []string{"/usr/bin/game"}}}})
	pe.Enforce(context.Background())
	for line := range strings.Lines(rulesOf(t, pe)) {
		if !strings.HasPrefix(line, "#") && !strings.Contains(line, "uid=2007") {
			t.Fatalf("a rule for everyone got in: %q", line)
		}
	}
	status := pe.Status()
	if len(status.Deviations) == 0 || strings.Contains(status.Deviations[0].Item, "\n") {
		t.Fatalf("got %+v", status)
	}
}

func TestPathsThatCannotStandInARule(t *testing.T) {
	for path, want := range map[string]bool{
		"/usr/bin/kate":      true,
		"/opt/My App/foo":    false,
		"/home/mia/game":     false,
		"/var/home/mia/game": false,
		"/tmp/x":             false,
		"/usr/bin/x\ny":      false,
		"/run/media/mia/x":   false,
		"/usr/../etc/passwd": false,
	} {
		if got := usablePath(path); got != want {
			t.Errorf("%q: got %v", path, got)
		}
	}
}

func TestAFailedLoadIsTriedAgain(t *testing.T) {
	pe, system := appsEngine(t)
	failing := true
	base := pe.exec.Run
	pe.exec.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "fagenrules" && failing {
			return "bad rule", errors.New("exit status 1")
		}
		return base(ctx, name, args...)
	}
	setPolicy(t, pe, api.Policy{Apps: []api.AppRule{{User: "mia", BlockDownloads: true}}})
	pe.Enforce(context.Background())
	if len(pe.Status().Deviations) == 0 {
		t.Fatal("no report")
	}
	failing = false
	system.calls = nil
	pe.Enforce(context.Background())
	if called(system.calls, "fagenrules --load") != 1 || len(pe.Status().Deviations) != 0 {
		t.Fatalf("not tried again: %v %+v", system.calls, pe.Status())
	}
}

func TestSessionProgramsCannotBeForbidden(t *testing.T) {
	pe, _ := appsEngine(t)
	addProgram(t, pe.exec, "plasmashell")
	setPolicy(t, pe, api.Policy{Apps: []api.AppRule{{User: "mia", ForbiddenPrograms: []string{"/usr/bin/plasmashell"}}}})
	pe.Enforce(context.Background())
	if strings.Contains(rulesOf(t, pe), "plasmashell") {
		t.Fatal("a rule took the desktop away")
	}
}

// A launcher that was not chosen cannot take python away, a parent can.
func TestInterpretersOnlyGoWhenNamed(t *testing.T) {
	pe, _ := appsEngine(t)
	addProgram(t, pe.exec, "python3")
	addLauncher(t, pe.exec, "tool", "[Desktop Entry]\nType=Application\nName=Tool\nExec=python3 /usr/lib/tool.py\n")
	e := pe.exec
	if rules := e.fapolicydRules(map[string]api.AppRule{"2007": {Strict: true}}, e.launchers(), false).text; strings.Contains(rules, "path=/usr/bin/python3") {
		t.Fatalf("got %s", rules)
	}
	named := api.AppRule{ForbiddenPrograms: []string{"/usr/bin/python3"}}
	if rules := e.fapolicydRules(map[string]api.AppRule{"2007": named}, nil, false).text; !strings.Contains(rules, "path=/usr/bin/python3") {
		t.Fatalf("got %s", rules)
	}
}

func TestEscapeTools(t *testing.T) {
	pe, _ := appsEngine(t)
	for _, tool := range []string{"unshare", "fusermount3", "bwrap"} {
		addProgram(t, pe.exec, tool)
	}
	e := pe.exec
	strict := e.fapolicydRules(map[string]api.AppRule{"2007": {User: "mia", Strict: true}}, nil, false).text
	for _, want := range []string{"path=/usr/bin/unshare", "path=/usr/bin/fusermount3", "path=/usr/bin/bwrap"} {
		if !strings.Contains(strict, want) {
			t.Errorf("no %s", want)
		}
	}
	flatpaks := api.AppRule{User: "mia", Strict: true, Flatpaks: &api.FlatpakList{Mode: api.FlatpakAllow, Apps: []string{"a"}}}
	rules := e.fapolicydRules(map[string]api.AppRule{"2007": flatpaks}, nil, false).text
	if strings.Contains(rules, "bwrap") || strings.Contains(rules, "fusermount3") {
		t.Fatalf("took away what Flatpaks need: %s", rules)
	}
	drive := e.fapolicydRules(map[string]api.AppRule{"2007": {User: "mia", Strict: true}}, nil, true).text
	if strings.Contains(drive, "fusermount3") {
		t.Fatalf("took away what the drive needs: %s", drive)
	}
}

func TestConfigurationWatchesSticksAndComesBack(t *testing.T) {
	pe, _ := appsEngine(t)
	config := pe.exec.path(fapolicydConfig)
	if err := os.MkdirAll(filepath.Dir(config), 0o755); err != nil {
		t.Fatal(err)
	}
	original := "permissive = 1\nintegrity = sha256\nwatch_fs = ext4,zfs\nallow_filesystem_mark = 0\n"
	if err := os.WriteFile(config, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	setPolicy(t, pe, api.Policy{Apps: []api.AppRule{{User: "mia", BlockDownloads: true}}})
	pe.Enforce(context.Background())
	raw, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"permissive = 0", "integrity = none", "allow_filesystem_mark = 1", "watch_fs = ext4,zfs,vfat,exfat"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("no %q in %s", want, raw)
		}
	}
	if strings.Contains(string(raw), "cifs") {
		t.Fatal("a hanging server would hold up every program")
	}
	if err := pe.Clear(); err != nil {
		t.Fatal(err)
	}
	pe.Enforce(context.Background())
	if raw, err := os.ReadFile(config); err != nil || string(raw) != original {
		t.Fatalf("%q %v", raw, err)
	}
}

func TestCrashHalfWayIsCleanedUp(t *testing.T) {
	pe, _ := appsEngine(t)
	if err := os.MkdirAll(pe.exec.path(fapolicydOriginal), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pe.exec.path(fapolicydOriginal+"/30.rules"), []byte("shipped"), 0o644); err != nil {
		t.Fatal(err)
	}
	pe.Enforce(context.Background())
	if raw, err := os.ReadFile(pe.exec.path(fapolicydRulesDir + "/30.rules")); err != nil || string(raw) != "shipped" {
		t.Fatalf("%q %v", raw, err)
	}
}

func TestAnEnabledServiceStaysEnabled(t *testing.T) {
	pe, system := appsEngine(t)
	base := pe.exec.Run
	pe.exec.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "systemctl" && args[0] == "is-enabled" {
			return "", nil
		}
		return base(ctx, name, args...)
	}
	setPolicy(t, pe, api.Policy{Apps: []api.AppRule{{User: "mia", BlockDownloads: true}}})
	pe.Enforce(context.Background())
	if err := pe.Clear(); err != nil {
		t.Fatal(err)
	}
	system.calls = nil
	pe.Enforce(context.Background())
	if called(system.calls, "systemctl disable --now fapolicyd") != 0 || called(system.calls, "systemctl restart fapolicyd") != 1 {
		t.Fatalf("got %v", system.calls)
	}
}

func TestAccountsDaemonIsRestartedOnce(t *testing.T) {
	pe, system := appsEngine(t)
	base := pe.exec.Run
	pe.exec.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "busctl" && slices.Contains(args, "set-property") {
			return "", errors.New("exit status 1")
		}
		return base(ctx, name, args...)
	}
	setPolicy(t, pe, api.Policy{Apps: []api.AppRule{{User: "mia", Flatpaks: &api.FlatpakList{Mode: api.FlatpakAllow}}}})
	pe.Enforce(context.Background())
	pe.Enforce(context.Background())
	if called(system.calls, "systemctl restart accounts-daemon") != 1 {
		t.Fatalf("got %v", system.calls)
	}
	if len(pe.Status().Deviations) == 0 {
		t.Fatal("no report")
	}
}

func TestFiltersOfThoseWhoAreGoneAreForgotten(t *testing.T) {
	pe, _ := appsEngine(t)
	pe.state.AppFilters = []string{"99999"}
	base := pe.exec.Run
	pe.exec.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "getent" {
			return "", errors.New("exit status 2")
		}
		return base(ctx, name, args...)
	}
	pe.Enforce(context.Background())
	if len(pe.state.AppFilters) != 0 {
		t.Fatalf("got %v", pe.state.AppFilters)
	}
}

// Someone else got the number of a deleted account.
func TestPinnedIDOfALocalAccountIsNotTrusted(t *testing.T) {
	pe, _ := appsEngine(t)
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	pe.state.ScreenUIDs = map[string]string{"gone": me.Uid}
	base := pe.exec.Run
	pe.exec.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "getent" {
			return "", errors.New("exit status 2")
		}
		return base(ctx, name, args...)
	}
	if got := pe.accounts("gone"); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}
