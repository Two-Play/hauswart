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

func testDirectory() *api.DirectoryRule {
	return &api.DirectoryRule{URI: "ldaps://auth.example:636", BaseDN: "dc=ldap,dc=goauthentik,dc=io", BindDN: "cn=reader,ou=users,dc=ldap", BindPassword: "s3cret", CA: testPEM}
}

// directorySystem fakes a Fedora with authselect.
type directorySystem struct {
	fakeSystem
	selected string
	failPAM  bool
	profiles int
	selects  []string
	// createProfile does what authselect does for a new profile.
	createProfile func() error
}

func (d *directorySystem) run(ctx context.Context, name string, args ...string) (string, error) {
	switch name {
	case "authselect":
		if args[0] == "current" {
			return d.selected, nil
		}
		if args[0] == "select" {
			d.selects = append(d.selects, strings.Join(args[1:], " "))
		}
		if args[0] == "create-profile" {
			d.profiles++
			return "", d.createProfile()
		}
		if d.failPAM {
			return "no", errors.New("exit status 1")
		}
		d.selected = strings.Join(slices.DeleteFunc(slices.Clone(args[1:]), func(a string) bool { return strings.HasPrefix(a, "--") }), " ")
		d.calls = append(d.calls, append([]string{name}, args...))
		return "", nil
	}
	return d.fakeSystem.run(ctx, name, args...)
}

func newDirectoryEngine(t *testing.T) (*PolicyEngine, *directorySystem) {
	t.Helper()
	pe, base := newEngine(t)
	system := &directorySystem{fakeSystem: *base}
	system.createProfile = func() error {
		dir := pe.exec.path(mountProfileDir)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		template := "auth required pam_env.so\nauth sufficient pam_unix.so nullok\nauth sufficient pam_sss.so forward_pass\nauth required pam_deny.so\nsession required pam_unix.so\nsession optional pam_sss.so\n"
		for _, name := range []string{"system-auth", "password-auth"} {
			if err := os.WriteFile(dir+"/"+name, []byte(template), 0o644); err != nil {
				return err
			}
		}
		return nil
	}
	pe.exec.Run = system.run
	pe.exec.Has = func(name string) bool { return name == authselectTool }
	return pe, system
}

func called(calls [][]string, want string) int {
	n := 0
	for _, call := range calls {
		if strings.Join(call, " ") == want {
			n++
		}
	}
	return n
}

func TestDirectorySetsUpTheLogin(t *testing.T) {
	pe, system := newDirectoryEngine(t)
	setPolicy(t, pe, api.Policy{Directory: testDirectory()})
	pe.Enforce(context.Background())

	status := pe.Status()
	if len(status.Deviations) != 0 || status.Checks["directory"] != checkOn {
		t.Fatalf("got %+v", status)
	}
	for _, pkg := range sssdPackages[authselectTool] {
		if !system.packages[pkg] {
			t.Errorf("%s was not installed", pkg)
		}
	}
	info, err := os.Stat(pe.exec.path(sssdConfig))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%v, %v", info, err)
	}
	raw, _ := os.ReadFile(pe.exec.path(sssdConfig))
	for _, want := range []string{"ldap_uri = ldaps://auth.example:636", "ldap_tls_reqcert = demand", "cache_credentials = true", "offline_credentials_expiration = 0", "ldap_default_authtok = s3cret", "ldap_tls_cacert = " + directoryCA, "min_id = 2000", "filter_users = "} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("no %q in %s", want, raw)
		}
	}
	if called(system.calls, "authselect select sssd with-mkhomedir --force --backup=hauswart") != 1 {
		t.Fatalf("got %v", system.calls)
	}
}

func TestDirectoryLeavesAWorkingLoginAlone(t *testing.T) {
	pe, system := newDirectoryEngine(t)
	setPolicy(t, pe, api.Policy{Directory: testDirectory()})
	pe.Enforce(context.Background())
	system.selected = "sssd with-mkhomedir"
	system.calls = nil
	pe.Enforce(context.Background())
	if called(system.calls, "systemctl restart sssd") != 0 || called(system.calls, "authselect select sssd with-mkhomedir --force --backup=hauswart") != 0 {
		t.Fatalf("got %v", system.calls)
	}
	if status := pe.Status(); status.Corrected != nil {
		t.Fatalf("got %+v", status)
	}
}

func TestDirectoryRestartsOnChange(t *testing.T) {
	pe, system := newDirectoryEngine(t)
	setPolicy(t, pe, api.Policy{Directory: testDirectory()})
	pe.Enforce(context.Background())
	system.calls = nil
	changed := testDirectory()
	changed.URI = "ldaps://other.example"
	setPolicy(t, pe, api.Policy{Directory: changed})
	pe.Enforce(context.Background())
	if called(system.calls, "systemctl restart sssd") != 1 {
		t.Fatalf("got %v", system.calls)
	}
}

func TestDirectoryNeedsAPamTool(t *testing.T) {
	pe, system := newDirectoryEngine(t)
	pe.exec.Has = func(string) bool { return false }
	setPolicy(t, pe, api.Policy{Directory: testDirectory()})
	pe.Enforce(context.Background())
	if status := pe.Status(); status.Checks["directory"] != checkOff || len(status.Deviations) != 1 {
		t.Fatalf("got %+v", status)
	}
	if len(system.packages) != 0 {
		t.Fatal("installed something it cannot use")
	}
}

func TestPamFailureIsReported(t *testing.T) {
	pe, system := newDirectoryEngine(t)
	system.failPAM = true
	setPolicy(t, pe, api.Policy{Directory: testDirectory()})
	pe.Enforce(context.Background())
	status := pe.Status()
	if status.Checks["directory"] != checkOff || !slices.Contains(deviationItems(status), "directory pam") {
		t.Fatalf("got %+v", status)
	}
}

func TestLeavingTheDirectoryRemovesTheConfiguration(t *testing.T) {
	pe, system := newDirectoryEngine(t)
	setPolicy(t, pe, api.Policy{Directory: testDirectory()})
	pe.Enforce(context.Background())
	system.calls = nil
	if err := pe.Clear(); err != nil {
		t.Fatal(err)
	}
	pe.Enforce(context.Background())
	if _, err := os.Stat(pe.exec.path(sssdConfig)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the password stayed on the device")
	}
	if called(system.calls, "systemctl restart sssd") != 1 {
		t.Fatalf("got %v", system.calls)
	}
}

func TestDirectoryAccountsAreFound(t *testing.T) {
	e, _ := newExecutor(t)
	e.Run = func(_ context.Context, name string, args ...string) (string, error) {
		if name == "getent" && args[1] == "lena-from-ldap" {
			return "lena-from-ldap:*:2001:2001:Lena:/home/lena-from-ldap:/bin/bash\n", nil
		}
		return "", errors.New("exit status 2")
	}
	u, err := e.lookupUser("lena-from-ldap")
	if err != nil || u.Uid != "2001" || u.HomeDir != "/home/lena-from-ldap" {
		t.Fatalf("%+v, %v", u, err)
	}
	if _, err := e.lookupUser("nobody-here"); err == nil {
		t.Fatal("found someone who does not exist")
	}
}

func TestSharesNeedTheDirectory(t *testing.T) {
	pe, _ := newDirectoryEngine(t)
	setPolicy(t, pe, api.Policy{Mounts: []api.MountRule{{Server: "nas", Share: "family", Folder: "Family"}}})
	pe.Enforce(context.Background())
	if got := deviationItems(pe.Status()); !slices.Equal(got, []string{"mount shares"}) {
		t.Fatalf("got %v", got)
	}
}

func TestSharesAreSetUpWithoutAPassword(t *testing.T) {
	pe, system := newDirectoryEngine(t)
	setPolicy(t, pe, api.Policy{Directory: testDirectory(), Mounts: []api.MountRule{{Server: "nas.home", Share: "family", Folder: "Family"}}})
	pe.Enforce(context.Background())
	if status := pe.Status(); len(status.Deviations) != 0 {
		t.Fatalf("got %+v", status)
	}
	raw, err := os.ReadFile(pe.exec.path(pamMountConfig))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{`server="nas.home"`, `path="family"`, `mountpoint="/media/%(USER)-Family"`, "timeout 8 mount.cifs", `%(before=\",\" OPTIONS)`, `uid="2000-`, "nosuid,nodev"} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in %s", want, text)
		}
	}
	if strings.Contains(text, "s3cret") {
		t.Fatal("a password reached the file everyone can read")
	}
	if called(system.calls, "authselect select custom/hauswart with-mkhomedir --force --backup=hauswart") != 1 {
		t.Fatalf("got %v", system.calls)
	}
	raw, err = os.ReadFile(pe.exec.path(mountProfileDir + "/password-auth"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	if !strings.Contains(lines[0], "pam_mount.so") {
		t.Fatalf("pam_mount has to come first: %s", raw)
	}
	if !strings.Contains(string(raw), "pam_sss.so forward_pass try_first_pass") {
		t.Fatalf("got %s", raw)
	}
	if !strings.Contains(string(raw), "session     optional                                     pam_mount.so") {
		t.Fatalf("got %s", raw)
	}

	// Patching a second time changes nothing.
	system.calls = nil
	system.selected = "custom/hauswart with-mkhomedir"
	pe.Enforce(context.Background())
	again, _ := os.ReadFile(pe.exec.path(mountProfileDir + "/password-auth"))
	if string(again) != string(raw) || system.profiles != 1 {
		t.Fatalf("got %s", again)
	}
	if !system.packages["pam_mount"] || !system.packages["cifs-utils"] {
		t.Fatalf("got %v", system.packages)
	}
}

func TestDroppedSharesLeaveAnEmptyList(t *testing.T) {
	pe, _ := newDirectoryEngine(t)
	setPolicy(t, pe, api.Policy{Directory: testDirectory(), Mounts: []api.MountRule{{Server: "nas", Share: "family", Folder: "Family"}}})
	pe.Enforce(context.Background())
	setPolicy(t, pe, api.Policy{Directory: testDirectory()})
	pe.Enforce(context.Background())
	raw, _ := os.ReadFile(pe.exec.path(pamMountConfig))
	if strings.Contains(string(raw), "<volume") {
		t.Fatalf("got %s", raw)
	}
}

func TestNextcloudClient(t *testing.T) {
	pe, system := newDirectoryEngine(t)
	setPolicy(t, pe, api.Policy{Nextcloud: &api.NextcloudRule{URL: "https://cloud.home", Mode: api.NextcloudClient}})
	pe.Enforce(context.Background())
	if !system.packages["nextcloud-client"] {
		t.Fatalf("got %v", system.packages)
	}
	raw, err := os.ReadFile(pe.exec.path(nextcloudAutostart))
	if err != nil || !strings.Contains(string(raw), "--overrideserverurl https://cloud.home") {
		t.Fatalf("%s, %v", raw, err)
	}
}

func TestNextcloudDriveKeepsThePasswordInTheKeyring(t *testing.T) {
	pe, system := newDirectoryEngine(t)
	setPolicy(t, pe, api.Policy{Nextcloud: &api.NextcloudRule{URL: "https://cloud.home", Mode: api.NextcloudDrive}})
	pe.Enforce(context.Background())
	raw, err := os.ReadFile(pe.exec.path(nextcloudScript))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "secret-tool lookup") || strings.Contains(string(raw), "--webdav-pass") {
		t.Fatalf("got %s", raw)
	}
	if called(system.calls, "systemctl --global enable hauswart-nextcloud.service") == 0 {
		t.Fatalf("got %v", system.calls)
	}
	if err := pe.Clear(); err != nil {
		t.Fatal(err)
	}
	pe.Enforce(context.Background())
	if _, err := os.Stat(pe.exec.path(nextcloudScript)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the script stayed")
	}
	if called(system.calls, "systemctl --global disable hauswart-nextcloud.service") != 1 {
		t.Fatalf("got %v", system.calls)
	}
}

func TestUnusualPortIsAllowedInSELinux(t *testing.T) {
	pe, system := newDirectoryEngine(t)
	pe.exec.Has = func(name string) bool { return name == authselectTool || name == "selinuxenabled" }
	var calls []string
	base := pe.exec.Run
	listed := "ldap_port_t  tcp  389, 636, 3268\nhttp_port_t tcp 6636\n"
	pe.exec.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "semanage" {
			calls = append(calls, strings.Join(args, " "))
			if args[0] == "port" && args[1] == "-l" {
				return listed, nil
			}
			listed = "ldap_port_t tcp 6636, 389, 636\n"
			return "", nil
		}
		return base(ctx, name, args...)
	}
	rule := testDirectory()
	rule.URI = "ldaps://auth.example:6636"
	setPolicy(t, pe, api.Policy{Directory: rule})
	pe.Enforce(context.Background())
	if !slices.Contains(calls, "port -a -t ldap_port_t -p tcp 6636") || !system.packages[selinuxTools] {
		t.Fatalf("got %v", calls)
	}
	calls = nil
	pe.Enforce(context.Background())
	if slices.Contains(calls, "port -a -t ldap_port_t -p tcp 6636") {
		t.Fatalf("added the port twice: %v", calls)
	}
}

func TestUsualPortNeedsNothing(t *testing.T) {
	pe, system := newDirectoryEngine(t)
	pe.exec.Has = func(name string) bool { return name == authselectTool || name == "selinuxenabled" }
	setPolicy(t, pe, api.Policy{Directory: testDirectory()}) // port 636
	pe.Enforce(context.Background())
	if system.packages[selinuxTools] {
		t.Fatal("installed tools it does not need")
	}
}

// The real stack of authselect's sssd profile. Its jumps count modules, so nothing
// may land between a jump and its target.
func TestPamMountLeavesTheJumpsAlone(t *testing.T) {
	stack := `auth        required                                     pam_env.so
auth        [default=1 ignore=ignore success=ok]         pam_usertype.so isregular
auth        [default=1 ignore=ignore success=ok]         pam_localuser.so
auth        sufficient                                   pam_unix.so nullok
auth        [default=1 ignore=ignore success=ok]         pam_usertype.so isregular
auth        sufficient                                   pam_sss.so forward_pass
auth        required                                     pam_deny.so
session     optional                                     pam_keyinit.so revoke
session     required                                     pam_unix.so
`
	patched, err := withPamMount(stack)
	if err != nil {
		t.Fatal(err)
	}
	jumpFrom := -1
	for i, line := range strings.Split(patched, "\n") {
		if strings.Contains(line, "default=1") && strings.Contains(line, "isregular") {
			jumpFrom = i
		}
	}
	lines := strings.Split(patched, "\n")
	if !strings.Contains(lines[jumpFrom+1], "pam_sss.so") {
		t.Fatalf("something sits behind the jump: %s", patched)
	}
	if !strings.Contains(lines[0], "pam_mount.so") {
		t.Fatalf("got %s", patched)
	}
	if again, _ := withPamMount(patched); again != patched {
		t.Fatal("patched twice")
	}
}

// Otherwise a directory account named like a local one logs in as that person.
func TestLocalAccountsStayOutOfTheDirectory(t *testing.T) {
	pe, _ := newDirectoryEngine(t)
	passwd := pe.exec.path("/etc/passwd")
	if err := os.MkdirAll(pe.exec.path("/etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passwd, []byte("root:x:0:0::/root:/bin/bash\nparent:x:1000:1000::/home/parent:/bin/bash\nevil,name = x:x:1:1::/:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	setPolicy(t, pe, api.Policy{Directory: testDirectory()})
	pe.Enforce(context.Background())
	raw, _ := os.ReadFile(pe.exec.path(sssdConfig))
	if !strings.Contains(string(raw), "filter_users = parent,root\n") {
		t.Fatalf("got %s", raw)
	}

	// A new local account counts from the next check on.
	if err := os.WriteFile(passwd, []byte("root:x:0:0::/root:/bin/bash\nparent:x:1000:1000::/home/parent:/bin/bash\nanna:x:1001:1001::/home/anna:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pe.Enforce(context.Background())
	raw, _ = os.ReadFile(pe.exec.path(sssdConfig))
	if !strings.Contains(string(raw), "filter_users = anna,parent,root\n") {
		t.Fatalf("got %s", raw)
	}
}

func TestDirectoryTrustsOnlyItsOwnCA(t *testing.T) {
	pe, system := newDirectoryEngine(t)
	setPolicy(t, pe, api.Policy{Directory: testDirectory()})
	pe.Enforce(context.Background())
	raw, err := os.ReadFile(pe.exec.path(directoryCA))
	if err != nil || string(raw) != testPEM {
		t.Fatalf("%s, %v", raw, err)
	}
	system.calls = nil
	changed := testDirectory()
	changed.CA = strings.Replace(testPEM, "fake", "othr", 1)
	setPolicy(t, pe, api.Policy{Directory: changed})
	pe.Enforce(context.Background())
	if called(system.calls, "systemctl restart sssd") != 1 {
		t.Fatalf("a new CA did not reach sssd: %v", system.calls)
	}
}

func TestAnotherDirectoryStartsWithAnEmptyCache(t *testing.T) {
	pe, _ := newDirectoryEngine(t)
	setPolicy(t, pe, api.Policy{Directory: testDirectory()})
	pe.Enforce(context.Background())
	cache := pe.exec.path(sssdCache)
	if err := os.MkdirAll(filepath.Dir(cache), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, []byte("old passwords"), 0o600); err != nil {
		t.Fatal(err)
	}
	same := testDirectory()
	same.BindPassword = "rotated"
	setPolicy(t, pe, api.Policy{Directory: same})
	pe.Enforce(context.Background())
	if _, err := os.Stat(cache); err != nil {
		t.Fatal("a new reading password cost the offline logins")
	}
	other := testDirectory()
	other.URI = "ldaps://other.example"
	setPolicy(t, pe, api.Policy{Directory: other})
	pe.Enforce(context.Background())
	if _, err := os.Stat(cache); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the cache of the old directory stayed")
	}
}

func TestExistingAuthselectFeaturesStay(t *testing.T) {
	pe, system := newDirectoryEngine(t)
	system.selected = "local with-pam-u2f-2fa with-mdns4"
	setPolicy(t, pe, api.Policy{Directory: testDirectory()})
	pe.Enforce(context.Background())
	if len(system.selects) != 1 || system.selects[0] != "sssd with-pam-u2f-2fa with-mdns4 with-mkhomedir --force --backup=hauswart" {
		t.Fatalf("got %v", system.selects)
	}
}

// The templates of the installed authselect, where there is one.
func TestPamMountOnTheRealTemplates(t *testing.T) {
	for _, name := range []string{"system-auth", "password-auth"} {
		raw, err := os.ReadFile("/usr/share/authselect/default/sssd/" + name)
		if err != nil {
			t.Skip("no authselect here")
		}
		patched, err := withPamMount(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(patched, "\n")
		first := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "auth") })
		if !strings.Contains(lines[first], "pam_mount.so") {
			t.Errorf("%s: pam_mount is not first", name)
		}
		// Apart from that, every line stays where it was, so no jump changes.
		var rest []string
		for _, line := range lines {
			if !strings.Contains(line, "pam_mount.so") {
				rest = append(rest, strings.ReplaceAll(line, " try_first_pass", ""))
			}
		}
		if got, want := strings.TrimSpace(strings.Join(rest, "\n")), strings.TrimSpace(strings.ReplaceAll(string(raw), " try_first_pass", "")); got != want {
			t.Errorf("%s: the template changed:\n%s", name, got)
		}
	}
}
