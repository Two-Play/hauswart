package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
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

	backupSuffix = ".before-hauswart"
	maxLaunchers = 500

	accountsService = "org.freedesktop.Accounts"
	appFilterIface  = "com.endlessm.ParentalControls.AppFilter"
)

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

// launcherHelpers start the real application for a launcher. Other applications
// need them too, so a launcher that was not chosen cannot take them away. A rule
// that names one of them is another matter: someone decided that.
var launcherHelpers = map[string]bool{
	"python3": true, "python": true, "perl": true, "ruby": true, "pkexec": true, "gapplication": true, "dbus-send": true,
}

// launcherDirs are where the desktop finds what the system offers.
var launcherDirs = []string{"/usr/share/applications", "/usr/local/share/applications", "/var/lib/snapd/desktop/applications"}

// namespaceTools make a mount that no rule sees.
var namespaceTools = []string{"unshare", "nsenter"}

// stickFilesystems are added to what fapolicyd watches. Network shares are left out
// on purpose: a server that stopped answering would hold up every program on the
// device. Shares are mounted noexec instead.
var stickFilesystems = []string{"vfat", "exfat", "ntfs", "ntfs3", "fuseblk", "iso9660"}

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
		if api.ValidAppID(app.id) && len(entries) < maxLaunchers {
			entries = append(entries, api.AppEntry{ID: app.id, Name: app.name})
		}
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
	fields := strings.Fields(strings.NewReplacer(`"`, "", "'", "").Replace(line))
	for len(fields) > 0 {
		first := fields[0]
		switch {
		case filepath.Base(first) == "env" || strings.Contains(first, "="):
			fields = fields[1:]
		case first == "-u" && len(fields) > 1:
			fields = fields[2:]
		case strings.HasPrefix(first, "-"):
			fields = fields[1:]
		default:
			return first
		}
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
	var files []string
	for _, dir := range launcherDirs {
		if matches, err := filepath.Glob(e.path(dir + "/*.desktop")); err == nil {
			files = append(files, matches...)
		}
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
		first := execProgram(exec)
		program := e.resolveProgram(first)
		if program != "" && !neededByOthers(first) && !neededByOthers(program) {
			app.program = program
		}
		found = append(found, app)
	}
	return found
}

func neededByOthers(path string) bool {
	return sessionPrograms[filepath.Base(path)] || launcherHelpers[filepath.Base(path)]
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

// usablePath decides what may go into a rule file. Fields end at a space there and
// a line break starts a rule, so a path from the file system has to pass the same
// check as one from a policy. A place a person can write to is out as well: where
// a link there points to is theirs to choose.
func usablePath(path string) bool {
	return api.SafeProgramPath(path) && !api.InUserWritable(path)
}

// ruleSet is what a set of people is denied.
type ruleSet struct {
	text string
	// skipped are programs no rule could be written for.
	skipped []string
}

// fapolicydRules writes the rules for the given people. Rules look at the numeric
// ID, so a rename changes nothing. Whatever comes from the file system passes
// usablePath first, and everything else comes from checked rules.
func (e *Executor) fapolicydRules(rules map[string]api.AppRule, apps launcherList, drive bool) ruleSet {
	var set ruleSet
	var b strings.Builder
	b.WriteString("# Managed by Hauswart\n")
	for _, uid := range slices.Sorted(maps.Keys(rules)) {
		rule := rules[uid]
		if !rule.BlockDownloads && !rule.Strict && len(rule.ForbiddenPrograms) == 0 {
			continue
		}
		// Even a program that is forbidden on its own could otherwise be copied
		// home, or be run through the loader.
		fmt.Fprintf(&b, "deny_audit perm=any uid=%s pattern=ld_so : all\n", uid)
		fmt.Fprintf(&b, "deny_audit perm=any uid=%s pattern=ld_preload : all\n", uid)
		for _, dir := range api.UserWritable {
			fmt.Fprintf(&b, "deny_audit perm=execute uid=%s : dir=%s\n", uid, dir)
			fmt.Fprintf(&b, "deny_audit perm=open uid=%s : dir=%s ftype=application/x-sharedlib\n", uid, dir)
		}
		for _, script := range scriptTypes {
			program := e.resolveProgram(script.program)
			if program == "" || !usablePath(program) {
				continue
			}
			for _, kind := range script.types {
				for _, dir := range api.UserWritable {
					fmt.Fprintf(&b, "deny_audit perm=open uid=%s exe=%s : dir=%s ftype=%s\n", uid, program, dir, kind)
				}
			}
		}
		blocked, skipped := e.blockedPrograms(rule, apps, drive)
		set.skipped = append(set.skipped, skipped...)
		for _, program := range blocked {
			// Any access, so that a script cannot be read by its interpreter either.
			fmt.Fprintf(&b, "deny_audit perm=any uid=%s : path=%s\n", uid, program)
		}
	}
	set.text = b.String()
	return set
}

// blockedPrograms lists the files one rule denies, and what it could not deny.
func (e *Executor) blockedPrograms(rule api.AppRule, apps launcherList, drive bool) (blocked, skipped []string) {
	tools := slices.Clone(namespaceTools)
	// Flatpaks need bubblewrap and FUSE, and so does the Nextcloud drive.
	if rule.Strict && (rule.Flatpaks == nil || len(rule.Flatpaks.Apps) == 0) {
		tools = append(tools, "bwrap")
		if !drive {
			tools = append(tools, "fusermount3", "fusermount")
		}
	}
	for _, tool := range tools {
		if program := e.resolveProgram(tool); program != "" {
			blocked = append(blocked, program)
		}
	}
	for _, program := range rule.ForbiddenPrograms {
		resolved := e.resolveProgram(program)
		if resolved == "" {
			resolved = program
		}
		if sessionPrograms[filepath.Base(program)] || sessionPrograms[filepath.Base(resolved)] {
			skipped = append(skipped, program)
			continue
		}
		blocked = append(blocked, resolved)
	}
	if rule.Strict {
		blocked = append(blocked, strictBlocks(apps, rule.AllowedApps)...)
	}
	slices.Sort(blocked)
	blocked = slices.Compact(blocked)
	usable := blocked[:0]
	for _, program := range blocked {
		if usablePath(program) {
			usable = append(usable, program)
		} else {
			skipped = append(skipped, program)
		}
	}
	return usable, skipped
}

const allowEverythingElse = "# Managed by Hauswart\nallow perm=any all : all\n"

func (pe *PolicyEngine) enforceApps(ctx context.Context, policy api.Policy, o *outcome) {
	if len(policy.Apps) == 0 {
		pe.leaveApps(ctx, o)
		return
	}
	byUID := map[string]api.AppRule{}
	for _, rule := range policy.Apps {
		uids := pe.accounts(rule.User)
		if len(uids) == 0 {
			o.deviate(deviationApps, rule.User, "this user is not known on this device")
			continue
		}
		for _, uid := range uids {
			// Anything else is no person, and a mistake here could stop the system.
			if number, _ := strconv.Atoi(uid); number >= minUserUID && number != nobodyUID {
				byUID[uid] = rule
			} else {
				o.deviate(deviationApps, rule.User, "this is a system account")
			}
		}
	}
	drive := policy.Nextcloud != nil && policy.Nextcloud.Mode == api.NextcloudDrive
	pe.enforceExecRules(ctx, byUID, drive, o)
	pe.enforceFlatpakFilters(ctx, byUID, o)
}

func (pe *PolicyEngine) enforceExecRules(ctx context.Context, byUID map[string]api.AppRule, drive bool, o *outcome) {
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
	set := e.fapolicydRules(byUID, e.launchers(), drive)
	for _, program := range set.skipped {
		o.deviate(deviationApps, clip(cleanText(program), 120), "no rule can be written for this program")
	}
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(set.text)))
	pe.mu.Lock()
	applied := pe.state.AppRulesHash
	pe.mu.Unlock()
	if applied == sum && e.rulesInPlace(set.text) {
		if _, err := e.Run(ctx, "systemctl", "is-active", "--quiet", "fapolicyd"); err != nil {
			// Without the service nothing is blocked, so this is worth a report.
			o.corrected = append(o.corrected, "fapolicyd was not running")
			if out, err := e.Run(ctx, "systemctl", "enable", "--now", "fapolicyd"); err != nil {
				o.deviate(deviationApps, "fapolicyd", strings.TrimSpace(out+" "+err.Error()))
			}
		}
		return
	}
	if err := pe.rememberFapolicyd(ctx); err != nil {
		o.deviate(deviationApps, "fapolicyd", err)
		return
	}
	if err := e.writeFapolicydRules(ctx, set.text); err != nil {
		o.deviate(deviationApps, "fapolicyd", err)
		return
	}
	for _, step := range []string{"enable", "restart"} {
		if out, err := e.Run(ctx, "systemctl", step, "fapolicyd"); err != nil {
			o.deviate(deviationApps, "fapolicyd", strings.TrimSpace(out+" "+err.Error()))
			return
		}
	}
	// Only now, so that a failure above is tried again at the next check.
	pe.mu.Lock()
	pe.state.AppRulesHash = sum
	err := pe.saveState()
	pe.mu.Unlock()
	if err != nil {
		o.deviate(deviationApps, "state", err)
	}
	o.corrected = append(o.corrected, "app rules")
}

func (e *Executor) rulesInPlace(wanted string) bool {
	for _, path := range []string{fapolicydOurRules, fapolicydOneFile} {
		if raw, err := os.ReadFile(e.path(path)); err == nil && strings.Contains(string(raw), wanted) {
			return true
		}
	}
	return false
}

// rememberFapolicyd notes how the device was before the first rule. The copy of the
// configuration says that this has happened.
func (pe *PolicyEngine) rememberFapolicyd(ctx context.Context) error {
	e := pe.exec
	if _, err := os.Stat(e.path(fapolicydConfig + backupSuffix)); err == nil {
		return nil
	}
	_, enabled := e.Run(ctx, "systemctl", "is-enabled", "--quiet", "fapolicyd")
	pe.mu.Lock()
	pe.state.FapolicydBefore = enabled == nil
	err := pe.saveState()
	pe.mu.Unlock()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(e.path(fapolicydConfig))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(e.path(fapolicydDir), 0o755); err != nil {
		return err
	}
	return writeAtomic(e.path(fapolicydConfig+backupSuffix), raw, 0o644)
}

func (e *Executor) writeFapolicydRules(ctx context.Context, wanted string) error {
	if err := e.relaxFapolicydConfig(); err != nil {
		return err
	}
	if e.Has != nil && !e.Has("fagenrules") {
		return e.writeOneRuleFile(wanted)
	}
	// What the package brings along applies to everyone on the device. It is kept,
	// and it comes back with the end of the rules.
	if _, err := os.Stat(e.path(fapolicydOriginal)); errors.Is(err, os.ErrNotExist) {
		err := os.Rename(e.path(fapolicydRulesDir), e.path(fapolicydOriginal))
		if errors.Is(err, os.ErrNotExist) {
			err = os.MkdirAll(e.path(fapolicydOriginal), 0o755)
		}
		if err != nil {
			return err
		}
	}
	if err := os.MkdirAll(e.path(fapolicydRulesDir), 0o755); err != nil {
		return err
	}
	// Rules that turn up here later would apply to everyone.
	others, err := filepath.Glob(e.path(fapolicydRulesDir + "/*"))
	if err != nil {
		return err
	}
	for _, other := range others {
		name := filepath.Base(other)
		if name == filepath.Base(fapolicydOurRules) || name == filepath.Base(fapolicydAllowAll) {
			continue
		}
		if err := os.Rename(other, filepath.Join(e.path(fapolicydOriginal), name)); err != nil {
			return err
		}
	}
	if err := writeAtomic(e.path(fapolicydOurRules), []byte(wanted), 0o644); err != nil {
		return err
	}
	if err := writeAtomic(e.path(fapolicydAllowAll), []byte(allowEverythingElse), 0o644); err != nil {
		return err
	}
	if out, err := e.Run(ctx, "fagenrules", "--load"); err != nil {
		return fmt.Errorf("%w: %s", err, clip(out, maxDeviationText))
	}
	return nil
}

func (e *Executor) writeOneRuleFile(wanted string) error {
	full := e.path(fapolicydOneFile)
	current, err := os.ReadFile(full)
	if err == nil && !bytes.Contains(current, []byte("Managed by Hauswart")) {
		if err := writeAtomic(full+backupSuffix, current, 0o644); err != nil {
			return err
		}
	}
	return writeAtomic(full, []byte(wanted+strings.TrimPrefix(allowEverythingElse, "# Managed by Hauswart\n")), 0o644)
}

var (
	integrityRe  = regexp.MustCompile(`(?m)^integrity\s*=.*$`)
	permissiveRe = regexp.MustCompile(`(?m)^permissive\s*=.*$`)
	markRe       = regexp.MustCompile(`(?m)^allow_filesystem_mark\s*=.*$`)
	watchRe      = regexp.MustCompile(`(?m)^watch_fs\s*=.*$`)
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
	// A mark on the file system also reaches its mounts in other namespaces. Only
	// where the option is known, as the daemon may refuse what it does not know.
	out = markRe.ReplaceAll(out, []byte("allow_filesystem_mark = 1"))
	out = watchRe.ReplaceAllFunc(out, func(line []byte) []byte {
		_, value, _ := strings.Cut(string(line), "=")
		kinds := strings.Split(strings.ReplaceAll(value, " ", ""), ",")
		for _, kind := range stickFilesystems {
			if !slices.Contains(kinds, kind) {
				kinds = append(kinds, kind)
			}
		}
		return []byte("watch_fs = " + strings.Join(kinds, ","))
	})
	if bytes.Equal(out, raw) {
		return nil
	}
	return writeAtomic(full, out, 0o644)
}

func (pe *PolicyEngine) leaveApps(ctx context.Context, o *outcome) {
	pe.leaveExecRules(ctx, o)
	pe.enforceFlatpakFilters(ctx, nil, o)
}

// leaveExecRules puts back what was there before. A backup alone is reason enough,
// as a crash may have come between two steps of the way in or out.
func (pe *PolicyEngine) leaveExecRules(ctx context.Context, o *outcome) {
	e := pe.exec
	if !e.hasOurRules() {
		return
	}
	pe.mu.Lock()
	wasOn := pe.state.FapolicydBefore
	pe.mu.Unlock()
	if !wasOn {
		if out, err := e.Run(ctx, "systemctl", "disable", "--now", "fapolicyd"); err != nil {
			pe.log.Warn("stopping fapolicyd failed", "err", err, "output", clip(out, maxDeviationText))
		}
	}
	if err := e.restoreFapolicyd(); err != nil {
		o.deviate(deviationApps, "fapolicyd", err)
		return
	}
	// The compiled file still holds our rules, whether the service runs or not.
	if e.Has == nil || e.Has("fagenrules") {
		if out, err := e.Run(ctx, "fagenrules", "--load"); err != nil {
			pe.log.Warn("loading the shipped rules failed", "err", err, "output", clip(out, maxDeviationText))
		}
	}
	if wasOn {
		if out, err := e.Run(ctx, "systemctl", "restart", "fapolicyd"); err != nil {
			o.deviate(deviationApps, "fapolicyd", strings.TrimSpace(out+" "+err.Error()))
		}
	}
	pe.mu.Lock()
	pe.state.AppRulesHash, pe.state.FapolicydBefore = "", false
	err := pe.saveState()
	pe.mu.Unlock()
	if err != nil {
		o.deviate(deviationApps, "state", err)
	}
	o.corrected = append(o.corrected, "app rules removed")
}

func (e *Executor) hasOurRules() bool {
	for _, path := range []string{fapolicydOurRules, fapolicydOneFile} {
		if raw, err := os.ReadFile(e.path(path)); err == nil && bytes.Contains(raw, []byte("Managed by Hauswart")) {
			return true
		}
	}
	for _, path := range []string{fapolicydOriginal, fapolicydConfig + backupSuffix} {
		if _, err := os.Stat(e.path(path)); err == nil {
			return true
		}
	}
	return false
}

func (e *Executor) restoreFapolicyd() error {
	var errs []error
	if _, err := os.Stat(e.path(fapolicydOriginal)); err == nil {
		errs = append(errs, os.RemoveAll(e.path(fapolicydRulesDir)), os.Rename(e.path(fapolicydOriginal), e.path(fapolicydRulesDir)))
	}
	oneFile := e.path(fapolicydOneFile)
	err := os.Rename(oneFile+backupSuffix, oneFile)
	if errors.Is(err, os.ErrNotExist) {
		// Nothing to go back to, and our file must not stay either.
		err = nil
		if raw, readErr := os.ReadFile(oneFile); readErr == nil && bytes.Contains(raw, []byte("Managed by Hauswart")) {
			err = os.Remove(oneFile)
		}
	}
	errs = append(errs, err)
	if err := os.Rename(e.path(fapolicydConfig+backupSuffix), e.path(fapolicydConfig)); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
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
		return true, rule.Flatpaks.Mode == api.FlatpakAllow, rule.Flatpaks.Apps
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
		if limited, _, _ := wantedFilter(byUID[uid]); limited {
			wanted = append(wanted, uid)
		}
	}
	// Before anything else, so that a crash cannot leave a filter nobody knows about.
	pe.mu.Lock()
	remembered := slices.Clone(pe.state.AppFilters)
	for _, uid := range wanted {
		if !slices.Contains(remembered, uid) {
			remembered = append(remembered, uid)
		}
	}
	var err error
	if !slices.Equal(remembered, pe.state.AppFilters) {
		pe.state.AppFilters = remembered
		err = pe.saveState()
	}
	pe.mu.Unlock()
	if err != nil {
		o.deviate(deviationApps, "state", err)
		return
	}

	for _, uid := range wanted {
		rule := byUID[uid]
		if err := e.ensureFilterPackages(ctx, o); err != nil {
			o.deviate(deviationApps, "flatpak", err)
			break
		}
		_, allow, apps := wantedFilter(rule)
		if out, err := pe.setFilter(ctx, uid, allow, apps); err != nil {
			o.deviate(deviationApps, rule.User, strings.TrimSpace(out+" "+err.Error()))
			continue
		}
		// What someone installs for themselves would get past the list.
		if out, err := e.Run(ctx, "busctl", userInstallArgs(uid, false)...); err != nil {
			o.deviate(deviationApps, rule.User, strings.TrimSpace(out+" "+err.Error()))
		}
	}

	keep := slices.Clone(wanted)
	for _, uid := range remembered {
		if slices.Contains(wanted, uid) {
			continue
		}
		// An account that is gone took its filter with it.
		if _, known := e.userName(ctx, uid); !known {
			continue
		}
		if out, err := pe.setFilter(ctx, uid, false, nil); err != nil {
			o.deviate(deviationApps, uid, strings.TrimSpace(out+" "+err.Error()))
			keep = append(keep, uid)
			continue
		}
		e.Run(ctx, "busctl", userInstallArgs(uid, true)...)
	}
	if slices.Equal(remembered, keep) {
		return
	}
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.state.AppFilters = keep
	if err := pe.saveState(); err != nil {
		o.deviate(deviationApps, "state", err)
	}
}

func userInstallArgs(uid string, allowed bool) []string {
	return []string{"--system", "set-property", accountsService, "/org/freedesktop/Accounts/User" + uid,
		appFilterIface, "AllowUserInstallation", "b", strconv.FormatBool(allowed)}
}

func (pe *PolicyEngine) setFilter(ctx context.Context, uid string, allow bool, apps []string) (string, error) {
	e := pe.exec
	// AccountsService only has objects for those it was asked about, which matters
	// for accounts from a directory.
	find := func() {
		e.Run(ctx, "busctl", "--system", "call", accountsService, "/org/freedesktop/Accounts", accountsService, "FindUserById", "x", uid)
	}
	find()
	out, err := e.Run(ctx, "busctl", appFilterArgs(uid, allow, apps)...)
	if err == nil {
		return out, nil
	}
	pe.mu.Lock()
	again := !pe.accountsRestarted
	pe.accountsRestarted = true
	pe.mu.Unlock()
	if !again {
		return out, err
	}
	// A daemon that runs since before the package does not know the interface.
	e.Run(ctx, "systemctl", "restart", "accounts-daemon")
	find()
	return e.Run(ctx, "busctl", appFilterArgs(uid, allow, apps)...)
}

func (e *Executor) ensureFilterPackages(ctx context.Context, o *outcome) error {
	if e.Platform.Backend == nil {
		return errors.New("no supported package manager found")
	}
	packages := []string{"malcontent", "accountsservice"}
	before := len(o.deviations)
	converge(ctx, o, deviationPackage, packages, true, e.installedPackages, func(ctx context.Context, names []string) (string, error) {
		return e.packages(ctx, api.TaskPkgInstall, names)
	})
	if len(o.deviations) > before {
		return errors.New("the tools for Flatpak rules are missing")
	}
	return nil
}
