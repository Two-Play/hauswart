package agent

import (
	"context"
	"errors"
	"os"
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
	full := e.path(applicationsDir + "/" + id + ".desktop")
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
	if apps := pe.Status().Apps; len(apps) != 1 || apps[0].ID != "org.kde.kate" || apps[0].Name != "Kate" {
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
	if _, allow, _ := wantedFilter(api.AppRule{Strict: true, Flatpaks: &api.FlatpakList{Mode: api.FlatpakDeny, Apps: []string{"a"}}}); !allow {
		t.Fatal("a strict rule turned into a list of what is denied")
	}
	if limited, allow, apps := wantedFilter(api.AppRule{Strict: true}); !limited || !allow || len(apps) != 0 {
		t.Fatal("a strict rule left Flatpaks open")
	}
	if limited, _, _ := wantedFilter(api.AppRule{BlockDownloads: true}); limited {
		t.Fatal("limited Flatpaks nobody asked about")
	}
}
