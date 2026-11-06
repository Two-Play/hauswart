package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/Two-Play/hauswart/internal/api"
)

const (
	fapolicydDir      = "/etc/fapolicyd"
	fapolicydRulesDir = fapolicydDir + "/rules.d"
	fapolicydOriginal = fapolicydDir + "/rules.d.before-hauswart"
	fapolicydOurRules = fapolicydRulesDir + "/10-hauswart.rules"
	fapolicydAllowAll = fapolicydRulesDir + "/90-hauswart.rules"
	// Older versions have one file instead of a folder.
	fapolicydOneFile = fapolicydDir + "/fapolicyd.rules"
	fapolicydConfig  = fapolicydDir + "/fapolicyd.conf"

	applicationsDir = "/usr/share/applications"
	maxLaunchers    = 500

	accountsService = "org.freedesktop.Accounts"
	appFilterIface  = "com.endlessm.ParentalControls.AppFilter"
)

// userWritable are the places a person can put a program into.
var userWritable = []string{"/home/", "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"}

// Interpreters do the starting themselves, so the file they read has to be looked at.
var scriptTypes = []struct {
	program string
	types   []string
}{
	{"bash", []string{"text/x-shellscript"}},
	{"dash", []string{"text/x-shellscript"}},
	{"zsh", []string{"text/x-shellscript"}},
	{"python3", []string{"text/x-python", "text/x-script.python"}},
	{"perl", []string{"text/x-perl"}},
	{"ruby", []string{"text/x-ruby"}},
}

// sessionPrograms are never blocked by a strict rule, whatever their launcher says:
// without them there is no desktop, and no way for anyone to see what went wrong.
var sessionPrograms = map[string]bool{
	"gnome-shell": true, "gnome-session": true, "gnome-session-binary": true, "plasmashell": true,
	"kwin_wayland": true, "kwin_x11": true, "ksmserver": true, "startplasma-wayland": true, "startplasma-x11": true,
	"plasma_session": true, "krunner": true, "kded6": true, "kded5": true, "dbus-launch": true, "dbus-run-session": true,
	"sh": true, "bash": true, "dash": true, "env": true, "xdg-open": true, "gio": true, "flatpak": true, "systemctl": true,
	"hauswart-tray": true, "sddm": true, "gdm": true, "true": true, "false": true,
}

// launcher is an application that can be chosen.
type launcher struct {
	id, name string
	// program is the real file behind it, empty if there is none to block.
	program string
}

type launcherList []launcher

func (l launcherList) entries() []api.AppEntry {
	entries := make([]api.AppEntry, 0, len(l))
	for _, app := range l {
		entries = append(entries, api.AppEntry{ID: app.id, Name: app.name})
	}
	return entries
}

// parseLauncher reads a .desktop file. Only what a person sees in a menu counts.
func parseLauncher(text string) (name, exec string, ok bool) {
	section, kind, hidden := "", "", false
	for line := range strings.Lines(text) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		if section != "[Desktop Entry]" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch key {
		case "Name":
			name = value
		case "Exec":
			exec = value
		case "Type":
			kind = value
		case "NoDisplay", "Hidden":
			hidden = hidden || value == "true"
		}
	}
	return name, exec, kind == "Application" && !hidden && exec != "" && name != ""
}

// execProgram finds the program in an Exec line, past an env in front of it.
func execProgram(line string) string {
	fields := strings.Fields(strings.ReplaceAll(line, `"`, ""))
	for len(fields) > 0 {
		first := fields[0]
		if filepath.Base(first) == "env" || strings.Contains(first, "=") {
			fields = fields[1:]
			continue
		}
		return first
	}
	return ""
}

// resolveProgram follows links, as a rule is about the file that really runs.
func (e *Executor) resolveProgram(name string) string {
	candidates := []string{name}
	if !strings.HasPrefix(name, "/") {
		candidates = []string{"/usr/bin/" + name, "/usr/sbin/" + name, "/usr/libexec/" + name}
	}
	root, err := filepath.EvalSymlinks(e.path("/"))
	if err != nil {
		return ""
	}
	for _, candidate := range candidates {
		resolved, err := filepath.EvalSymlinks(e.path(candidate))
		if err != nil {
			continue
		}
		if rel, err := filepath.Rel(root, resolved); err == nil && !strings.HasPrefix(rel, "..") {
			return "/" + rel
		}
	}
	return ""
}

// launchers lists the applications of this device.
func (e *Executor) launchers() launcherList {
	files, err := filepath.Glob(e.path(applicationsDir + "/*.desktop"))
	if err != nil {
		return nil
	}
	var found launcherList
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		name, exec, ok := parseLauncher(string(raw))
		if !ok {
			continue
		}
		app := launcher{id: strings.TrimSuffix(filepath.Base(file), ".desktop"), name: clip(cleanText(name), 80)}
		if program := e.resolveProgram(execProgram(exec)); program != "" && !sessionPrograms[filepath.Base(program)] {
			app.program = program
		}
		found = append(found, app)
		if len(found) == maxLaunchers {
			break
		}
	}
	return found
}

// strictBlocks says which programs a strict rule stops. A program that an allowed
// launcher uses stays, even if another launcher of it was not chosen.
func strictBlocks(apps launcherList, allowed []string) []string {
	keep := map[string]bool{}
	for _, app := range apps {
		if slices.Contains(allowed, app.id) {
			keep[app.program] = true
		}
	}
	var blocked []string
	for _, app := range apps {
		if app.program != "" && !keep[app.program] {
			blocked = append(blocked, app.program)
		}
	}
	slices.Sort(blocked)
	return slices.Compact(blocked)
}

// fapolicydRules writes the rules for the given people. Rules look at the numeric
// ID, so a rename changes nothing. All values come from checked rules or from the
// device itself.
func (e *Executor) fapolicydRules(rules map[string]api.AppRule, apps launcherList) string {
	var b strings.Builder
	b.WriteString("# Managed by Hauswart\n")
	for _, uid := range slices.Sorted(maps.Keys(rules)) {
		rule := rules[uid]
		if rule.BlockDownloads || rule.Strict {
			fmt.Fprintf(&b, "deny_audit perm=any uid=%s pattern=ld_so : all\n", uid)
			for _, dir := range userWritable {
				fmt.Fprintf(&b, "deny_audit perm=execute uid=%s : dir=%s\n", uid, dir)
			}
			for _, script := range scriptTypes {
				program := e.resolveProgram(script.program)
				if program == "" {
					continue
				}
				for _, kind := range script.types {
					for _, dir := range userWritable {
						fmt.Fprintf(&b, "deny_audit perm=open uid=%s exe=%s : dir=%s ftype=%s\n", uid, program, dir, kind)
					}
				}
			}
		}
		for _, program := range rule.ForbiddenPrograms {
			path := program
			if resolved := e.resolveProgram(program); resolved != "" {
				path = resolved
			}
			fmt.Fprintf(&b, "deny_audit perm=execute uid=%s : path=%s\n", uid, path)
		}
		if rule.Strict {
			for _, program := range strictBlocks(apps, rule.AllowedApps) {
				fmt.Fprintf(&b, "deny_audit perm=execute uid=%s : path=%s\n", uid, program)
			}
		}
	}
	return b.String()
}

const allowEverythingElse = "# Managed by Hauswart\nallow perm=any all : all\n"

func (pe *PolicyEngine) enforceApps(ctx context.Context, rules []api.AppRule, o *outcome) {
	if len(rules) == 0 {
		pe.leaveApps(ctx, o)
		return
	}
	byUID := map[string]api.AppRule{}
	for _, rule := range rules {
		uids := pe.accounts(rule.User)
		if len(uids) == 0 {
			o.deviate(deviationApps, rule.User, "this user is not known on this device")
			continue
		}
		for _, uid := range uids {
			// An ID below this is no person, and a mistake here could stop the system.
			if number, _ := strconv.Atoi(uid); number >= minUserUID {
				byUID[uid] = rule
			}
		}
	}
	pe.enforceExecRules(ctx, byUID, o)
	pe.enforceFlatpakFilters(ctx, byUID, o)
}

func (pe *PolicyEngine) enforceExecRules(ctx context.Context, byUID map[string]api.AppRule, o *outcome) {
	e := pe.exec
	needed := false
	for _, rule := range byUID {
		needed = needed || rule.BlockDownloads || rule.Strict || len(rule.ForbiddenPrograms) > 0
	}
	if !needed {
		pe.leaveExecRules(ctx, o)
		return
	}
	if e.Platform.Backend == nil {
		o.deviate(deviationApps, "fapolicyd", "no supported package manager found")
		return
	}
	before := len(o.deviations)
	converge(ctx, o, deviationPackage, []string{"fapolicyd"}, true, e.installedPackages, func(ctx context.Context, names []string) (string, error) {
		return e.packages(ctx, api.TaskPkgInstall, names)
	})
	if len(o.deviations) > before {
		return
	}
	wanted := e.fapolicydRules(byUID, e.launchers())
	changed, err := e.writeFapolicydRules(ctx, wanted)
	if err != nil {
		o.deviate(deviationApps, "fapolicyd", err)
		return
	}
	if changed {
		o.corrected = append(o.corrected, "app rules")
		if out, err := e.Run(ctx, "systemctl", "enable", "fapolicyd"); err != nil {
			o.deviate(deviationApps, "fapolicyd", strings.TrimSpace(out+" "+err.Error()))
			return
		}
		if out, err := e.Run(ctx, "systemctl", "restart", "fapolicyd"); err != nil {
			o.deviate(deviationApps, "fapolicyd", strings.TrimSpace(out+" "+err.Error()))
			return
		}
		return
	}
	if _, err := e.Run(ctx, "systemctl", "is-active", "--quiet", "fapolicyd"); err != nil {
		// Without the service nothing is blocked, so this is worth a report.
		o.corrected = append(o.corrected, "fapolicyd was not running")
		if out, err := e.Run(ctx, "systemctl", "enable", "--now", "fapolicyd"); err != nil {
			o.deviate(deviationApps, "fapolicyd", strings.TrimSpace(out+" "+err.Error()))
		}
	}
}

func (e *Executor) writeFapolicydRules(ctx context.Context, wanted string) (bool, error) {
	if e.Has != nil && !e.Has("fagenrules") {
		return e.writeOneRuleFile(wanted)
	}
	current, err := os.ReadFile(e.path(fapolicydOurRules))
	if err == nil && string(current) == wanted {
		return false, nil
	}
	// What the package brings along applies to everyone on the device. It is kept,
	// and it comes back with the end of the rules.
	if _, err := os.Stat(e.path(fapolicydOriginal)); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(e.path(fapolicydRulesDir), e.path(fapolicydOriginal)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	if err := os.MkdirAll(e.path(fapolicydRulesDir), 0o755); err != nil {
		return false, err
	}
	if err := writeAtomic(e.path(fapolicydOurRules), []byte(wanted), 0o644); err != nil {
		return false, err
	}
	if err := writeAtomic(e.path(fapolicydAllowAll), []byte(allowEverythingElse), 0o644); err != nil {
		return false, err
	}
	if err := e.relaxFapolicydConfig(); err != nil {
		return false, err
	}
	if out, err := e.Run(ctx, "fagenrules", "--load"); err != nil {
		return false, fmt.Errorf("%w: %s", err, clip(out, maxDeviationText))
	}
	return true, nil
}

func (e *Executor) writeOneRuleFile(wanted string) (bool, error) {
	full := e.path(fapolicydOneFile)
	content := wanted + strings.TrimPrefix(allowEverythingElse, "# Managed by Hauswart\n")
	current, err := os.ReadFile(full)
	if err == nil && string(current) == content {
		return false, nil
	}
	if err == nil && !bytes.Contains(current, []byte("Managed by Hauswart")) {
		if err := writeAtomic(e.path(fapolicydOneFile+".before-hauswart"), current, 0o644); err != nil {
			return false, err
		}
	}
	if err := writeAtomic(full, []byte(content), 0o644); err != nil {
		return false, err
	}
	return true, e.relaxFapolicydConfig()
}

var (
	integrityRe  = regexp.MustCompile(`(?m)^integrity\s*=.*$`)
	permissiveRe = regexp.MustCompile(`(?m)^permissive\s*=.*$`)
)

// relaxFapolicydConfig leaves the decisions to the rules. Comparing file hashes
// would ask for a trust database that nothing here needs.
func (e *Executor) relaxFapolicydConfig() error {
	full := e.path(fapolicydConfig)
	raw, err := os.ReadFile(full)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	out := integrityRe.ReplaceAll(raw, []byte("integrity = none"))
	out = permissiveRe.ReplaceAll(out, []byte("permissive = 0"))
	if bytes.Equal(out, raw) {
		return nil
	}
	return writeAtomic(full, out, 0o644)
}

func (pe *PolicyEngine) leaveApps(ctx context.Context, o *outcome) {
	pe.leaveExecRules(ctx, o)
	pe.enforceFlatpakFilters(ctx, nil, o)
}

// leaveExecRules puts back what the package brought along, and stops the service,
// as those rules were never meant to apply here.
func (pe *PolicyEngine) leaveExecRules(ctx context.Context, o *outcome) {
	e := pe.exec
	ours := false
	for _, path := range []string{fapolicydOurRules, fapolicydOneFile} {
		if raw, err := os.ReadFile(e.path(path)); err == nil && bytes.Contains(raw, []byte("Managed by Hauswart")) {
			ours = true
		}
	}
	if !ours {
		return
	}
	if out, err := e.Run(ctx, "systemctl", "disable", "--now", "fapolicyd"); err != nil {
		pe.log.Warn("stopping fapolicyd failed", "err", err, "output", clip(out, maxDeviationText))
	}
	var errs []error
	if err := os.RemoveAll(e.path(fapolicydRulesDir)); err != nil {
		errs = append(errs, err)
	}
	if err := os.Rename(e.path(fapolicydOriginal), e.path(fapolicydRulesDir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	if err := os.Rename(e.path(fapolicydOneFile+".before-hauswart"), e.path(fapolicydOneFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		o.deviate(deviationApps, "fapolicyd", err)
		return
	}
	o.corrected = append(o.corrected, "app rules removed")
}

func flatpakArch() string {
	if runtime.GOARCH == "arm64" {
		return "aarch64"
	}
	return "x86_64"
}

// appFilterArgs are the arguments of busctl for a filter, which it reads as a
// value of the type (bas): is it a list of what is allowed, and the list.
func appFilterArgs(uid string, allow bool, apps []string) []string {
	args := []string{"--system", "set-property", accountsService, "/org/freedesktop/Accounts/User" + uid, appFilterIface, "AppFilter", "(bas)",
		strconv.FormatBool(allow), strconv.Itoa(len(apps))}
	for _, app := range apps {
		args = append(args, "app/"+app+"/"+flatpakArch()+"/stable")
	}
	return args
}

func wantedFilter(rule api.AppRule) (bool, bool, []string) {
	switch {
	case rule.Flatpaks != nil:
		// A strict rule has no room for a list of what is denied.
		return true, rule.Strict || rule.Flatpaks.Mode == api.FlatpakAllow, rule.Flatpaks.Apps
	case rule.Strict:
		return true, true, nil
	}
	return false, false, nil
}

// enforceFlatpakFilters limits Flatpaks through AccountsService, where flatpak
// itself looks. No tool of malcontent is needed for this.
func (pe *PolicyEngine) enforceFlatpakFilters(ctx context.Context, byUID map[string]api.AppRule, o *outcome) {
	e := pe.exec
	var wanted []string
	for _, uid := range slices.Sorted(maps.Keys(byUID)) {
		rule := byUID[uid]
		limited, allow, apps := wantedFilter(rule)
		if !limited {
			continue
		}
		wanted = append(wanted, uid)
		if err := e.ensureFilterPackages(ctx, o); err != nil {
			o.deviate(deviationApps, "flatpak", err)
			return
		}
		if out, err := e.Run(ctx, "busctl", appFilterArgs(uid, allow, apps)...); err != nil {
			o.deviate(deviationApps, rule.User, strings.TrimSpace(out+" "+err.Error()))
			continue
		}
		// What someone installs for themselves would get past the list.
		if out, err := e.Run(ctx, "busctl", "--system", "set-property", accountsService, "/org/freedesktop/Accounts/User"+uid,
			appFilterIface, "AllowUserInstallation", "b", "false"); err != nil {
			o.deviate(deviationApps, rule.User, strings.TrimSpace(out+" "+err.Error()))
		}
	}

	pe.mu.Lock()
	before := slices.Clone(pe.state.AppFilters)
	pe.mu.Unlock()
	for _, uid := range before {
		if slices.Contains(wanted, uid) {
			continue
		}
		if out, err := e.Run(ctx, "busctl", appFilterArgs(uid, false, nil)...); err != nil {
			o.deviate(deviationApps, uid, strings.TrimSpace(out+" "+err.Error()))
			wanted = append(wanted, uid)
			continue
		}
		e.Run(ctx, "busctl", "--system", "set-property", accountsService, "/org/freedesktop/Accounts/User"+uid,
			appFilterIface, "AllowUserInstallation", "b", "true")
	}
	if slices.Equal(before, wanted) {
		return
	}
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.state.AppFilters = wanted
	if err := pe.saveState(); err != nil {
		o.deviate(deviationApps, "state", err)
	}
}

func (e *Executor) ensureFilterPackages(ctx context.Context, o *outcome) error {
	if e.Platform.Backend == nil {
		return errors.New("no supported package manager found")
	}
	packages := []string{"malcontent", "accountsservice"}
	if e.Platform.Backend.Name == "apt" {
		packages = []string{"libmalcontent-0-0", "accountsservice"}
	}
	before := len(o.deviations)
	converge(ctx, o, deviationPackage, packages, true, e.installedPackages, func(ctx context.Context, names []string) (string, error) {
		return e.packages(ctx, api.TaskPkgInstall, names)
	})
	if len(o.deviations) > before {
		return errors.New("the tools for Flatpak rules are missing")
	}
	return nil
}
