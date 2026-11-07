package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"path"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // devices may lack the zone files, and a rule must not depend on that
)

// Task types of the desired state. Both need a signature: a policy decides what
// a device installs and trusts, and removing one would end parental controls.
const (
	TaskPolicySet   = "policy.set"
	TaskPolicyClear = "policy.clear"
	// TaskScreenExtend gives a user more time today, without a new policy.
	TaskScreenExtend = "screen.extend"
)

// MaxExtension caps a screen time extension. The agent also ends it at midnight,
// so that an approval on a phone never reaches past the day it was meant for.
const MaxExtension = 4 * time.Hour

// Reboot rules of automatic updates.
const (
	RebootNever  = "never"
	RebootWindow = "window"
)

const (
	maxPolicyBytes    = 1 << 20
	maxPolicyPackages = 200
	maxPolicyFiles    = 64
	maxPolicyCAs      = 16
	maxScreenRules    = 16
	maxRuleWindows    = 14
	reservedCA        = "server"
	maxBindPassword   = 256
	maxPolicyMounts   = 16
)

// Policy is the state a device keeps on its own. A group holds one, and what a
// device receives and an admin signs is the merge of the policies of its groups.
type Policy struct {
	RequiredPackages  []string           `json:"required_packages,omitempty"`
	ForbiddenPackages []string           `json:"forbidden_packages,omitempty"`
	RequiredFlatpaks  []string           `json:"required_flatpaks,omitempty"`
	ForbiddenFlatpaks []string           `json:"forbidden_flatpaks,omitempty"`
	Files             []FilePutPayload   `json:"files,omitempty"`
	CAs               []CAInstallPayload `json:"cas,omitempty"`
	Updates           *UpdateRule        `json:"updates,omitempty"`
	Security          *SecurityRule      `json:"security,omitempty"`
	// TimeZone is the zone of all time rules. It is part of the policy, so that
	// changing the zone of the device does not move a time window. Without it,
	// update windows use the device's own zone.
	TimeZone   string           `json:"time_zone,omitempty"`
	ScreenTime []ScreenTimeRule `json:"screen_time,omitempty"`
	// Language is that of the warnings a user sees, en or de.
	Language string `json:"language,omitempty"`
	// Directory lets accounts from an LDAP directory log in on the device.
	Directory *DirectoryRule `json:"directory,omitempty"`
	// Mounts are SMB shares that appear at login, with the login password. They
	// need Directory, because the share has to know the same password.
	Mounts []MountRule `json:"mounts,omitempty"`
	// Nextcloud sets up the shared cloud for everyone on the device.
	Nextcloud *NextcloudRule `json:"nextcloud,omitempty"`
	// Apps says what some people may start. Everyone else is left alone.
	Apps []AppRule `json:"apps,omitempty"`
}

// Modes of a FlatpakList.
const (
	FlatpakAllow = "allow"
	FlatpakDeny  = "deny"
)

// AppRule limits one user. Nothing here reaches anyone else on the device.
type AppRule struct {
	User string `json:"user"`
	// BlockDownloads stops programs from places a user can write to.
	BlockDownloads bool `json:"block_downloads,omitempty"`
	// ForbiddenPrograms are absolute paths.
	ForbiddenPrograms []string `json:"forbidden_programs,omitempty"`
	// Strict allows only the applications in AllowedApps, and blocks downloads and
	// all Flatpaks that are not listed. It is about applications with a launcher:
	// a desktop needs hundreds of helpers, which stay.
	Strict bool `json:"strict,omitempty"`
	// AllowedApps are launchers, as in org.kde.kate.
	AllowedApps []string     `json:"allowed_apps,omitempty"`
	Flatpaks    *FlatpakList `json:"flatpaks,omitempty"`
}

// FlatpakList allows or denies some Flatpaks, by their ID.
type FlatpakList struct {
	Mode string   `json:"mode"`
	Apps []string `json:"apps"`
}

// MountRule puts a share into the home directory, under Folder.
type MountRule struct {
	Server string `json:"server"`
	Share  string `json:"share"`
	Folder string `json:"folder"`
}

// How Nextcloud appears on a device.
const (
	// NextcloudClient installs the sync client and points it at the server.
	NextcloudClient = "client"
	// NextcloudDrive mounts the files without a local copy.
	NextcloudDrive = "drive"
)

// NextcloudRule holds no passwords. Each person logs in for themselves.
type NextcloudRule struct {
	URL  string `json:"url"`
	Mode string `json:"mode"`
}

// DirectoryRule points a device at an LDAP directory, such as the LDAP outpost
// of Authentik. The password belongs to a service account that may only read: it
// ends up on the server and on every device of the group.
type DirectoryRule struct {
	URI          string `json:"uri"`
	BaseDN       string `json:"base_dn"`
	BindDN       string `json:"bind_dn"`
	BindPassword string `json:"bind_password"`
	// CA is the one certificate authority this directory may use. It is not the
	// system store, which holds the CA of the Hauswart server: a hacked server could
	// then pose as the directory, and log in as anyone.
	CA string `json:"ca"`
}

// ScreenExtendPayload lets a user stay until a moment today. It is a moment and
// not a duration, so that a delayed task gives no more than was meant.
type ScreenExtendPayload struct {
	User  string    `json:"user"`
	Until time.Time `json:"until"`
}

// Window is a stretch of time on some days of the week. It stays within a day:
// an evening that runs past midnight is two windows.
type Window struct {
	Days  []string `json:"days"`
	Start string   `json:"start"` // 15:00
	End   string   `json:"end"`   // 19:00, or 24:00 for the end of the day
}

// UpdateRule runs updates in a maintenance window.
type UpdateRule struct {
	Window Window `json:"window"`
	Reboot string `json:"reboot"`
}

// SecurityRule says what a device has to do about its protection. The firewall
// can be enforced. The other two cannot be forced on a running system, so they
// are only checked and reported.
type SecurityRule struct {
	Firewall       bool `json:"firewall,omitempty"`
	DiskEncryption bool `json:"disk_encryption,omitempty"`
	ScreenLock     bool `json:"screen_lock,omitempty"`
}

// ScreenTimeRule says when a user may be logged in. A day without a window is a
// day without a session.
type ScreenTimeRule struct {
	User    string   `json:"user"`
	Windows []Window `json:"windows"`
}

// PolicyStatus is what a device reports about its policy.
type PolicyStatus struct {
	Hash       string            `json:"hash,omitempty"`
	CheckedAt  time.Time         `json:"checked_at,omitzero"`
	Deviations []PolicyDeviation `json:"deviations,omitempty"`
	// Checks holds the results of rules that can only be looked at, by name:
	// on, off or unknown.
	Checks map[string]string `json:"checks,omitempty"`
	// Corrected lists what the last check put right, which says that someone or
	// something changed the device.
	Corrected []string `json:"corrected,omitempty"`
}

// AppEntry is an application a device has.
type AppEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// PolicyDeviation is one point where a device differs from its policy.
type PolicyDeviation struct {
	Kind   string `json:"kind"`
	Item   string `json:"item"`
	Detail string `json:"detail,omitempty"`
}

// PolicyConflict names an entry on which policies contradict each other.
type PolicyConflict struct {
	Item   string   `json:"item"`
	Groups []string `json:"groups"`
}

var (
	appIDRe         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	shareRe         = regexp.MustCompile(`^[A-Za-z0-9._-]{1,80}$`)
	nextcloudRe     = regexp.MustCompile(`^https://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?(/[A-Za-z0-9._-]+)*$`)
	ldapURIRe       = regexp.MustCompile(`^ldaps://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$`)
	distinguishedRe = regexp.MustCompile(`^[A-Za-z0-9=,._ -]{1,255}$`)
	clockRe         = regexp.MustCompile(`^(([01][0-9]|2[0-3]):[0-5][0-9]|24:00)$`)
	weekday         = map[string]time.Weekday{
		"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
		"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
	}
)

// Without these a device stops working or stops being managed, and a package
// manager would remove them along with everything that depends on them.
var (
	protectedPackages = map[string]bool{
		"hauswart": true, "hauswart-agent": true, "sudo": true, "bash": true, "coreutils": true,
		"util-linux": true, "shadow-utils": true, "passwd": true, "login": true, "pam": true,
		"dbus": true, "polkit": true, "ca-certificates": true, "openssl": true,
		"rpm": true, "rpm-ostree": true, "dnf": true, "dnf5": true, "apt": true, "dpkg": true,
		"zypper": true, "pacman": true, "flatpak": true,
	}
	protectedPrefixes = []string{"kernel", "linux", "glibc", "libc6", "systemd", "grub", "shim"}
)

func protectedPackage(name string) bool {
	name = strings.ToLower(name)
	return protectedPackages[name] || slices.ContainsFunc(protectedPrefixes, func(prefix string) bool {
		return strings.HasPrefix(name, prefix)
	})
}

func init() {
	register(TaskPolicySet, false, CheckPolicy)
	register(TaskPolicyClear, false, func(struct{}) error { return nil })
	register(TaskScreenExtend, false, checkScreenExtend)
}

func checkScreenExtend(p ScreenExtendPayload) error {
	if !ValidUser(p.User) {
		return Fail(ErrInvalidUser, p.User)
	}
	if p.Until.IsZero() || time.Until(p.Until) > MaxExtension {
		return Fail(ErrInvalidExtension, MaxExtension.String())
	}
	return nil
}

// CheckPolicy applies the same rules to a group's policy and to a merged one.
func CheckPolicy(p Policy) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return Fail(ErrInvalidPayload, err.Error())
	}
	if len(raw) > maxPolicyBytes {
		return Fail(ErrPolicyTooLarge, strconv.Itoa(maxPolicyBytes>>10))
	}
	for _, list := range [][]string{p.RequiredPackages, p.ForbiddenPackages, p.RequiredFlatpaks, p.ForbiddenFlatpaks} {
		if len(list) > maxPolicyPackages {
			return Fail(ErrPolicyTooLarge, strconv.Itoa(maxPolicyBytes>>10))
		}
		for _, name := range list {
			if !ValidPackage(name) {
				return Fail(ErrInvalidPackage, name)
			}
		}
	}
	for _, name := range p.ForbiddenPackages {
		if protectedPackage(name) {
			return Fail(ErrPackageProtected, name)
		}
	}
	if len(p.Files) > maxPolicyFiles || len(p.CAs) > maxPolicyCAs || len(p.ScreenTime) > maxScreenRules {
		return Fail(ErrPolicyTooLarge, strconv.Itoa(maxPolicyBytes>>10))
	}
	for _, file := range p.Files {
		if err := checkFilePut(file); err != nil {
			return err
		}
		// Two spellings of one path would pass as two files and fight forever.
		if path.Clean(file.Path) != file.Path {
			return Fail(ErrInvalidPath, file.Path)
		}
	}
	for _, ca := range p.CAs {
		if err := checkCAInstall(ca); err != nil {
			return err
		}
		// That name is the server's own CA, which a device trusts from
		// enrollment on. Dropping it from a policy must not end that trust.
		if ca.Name == reservedCA {
			return Fail(ErrInvalidCAName, ca.Name)
		}
	}
	if p.TimeZone != "" {
		if _, err := time.LoadLocation(p.TimeZone); err != nil || p.TimeZone == "Local" {
			return Fail(ErrInvalidTimeZone, p.TimeZone)
		}
	}
	if p.Updates != nil {
		if err := checkTimeWindow(p.Updates.Window); err != nil {
			return err
		}
		if p.Updates.Reboot != RebootNever && p.Updates.Reboot != RebootWindow {
			return Fail(ErrInvalidReboot, p.Updates.Reboot)
		}
	}
	if len(p.ScreenTime) > 0 && p.TimeZone == "" {
		return Fail(ErrInvalidTimeZone, "")
	}
	if p.Language != "" && p.Language != "en" && p.Language != "de" {
		return Fail(ErrInvalidPayload, "language")
	}
	if p.Directory != nil {
		if err := checkDirectory(*p.Directory); err != nil {
			return err
		}
	}
	if len(p.Mounts) > maxPolicyMounts {
		return Fail(ErrPolicyTooLarge, strconv.Itoa(maxPolicyBytes>>10))
	}
	for _, mount := range p.Mounts {
		if !ValidHostName(mount.Server) || !shareRe.MatchString(mount.Share) || !shareRe.MatchString(mount.Folder) || strings.HasPrefix(mount.Folder, ".") {
			return Fail(ErrInvalidMount, mount.Server+"/"+mount.Share)
		}
	}
	if len(p.Apps) > maxScreenRules {
		return Fail(ErrPolicyTooLarge, strconv.Itoa(maxPolicyBytes>>10))
	}
	for _, rule := range p.Apps {
		if err := checkAppRule(rule); err != nil {
			return err
		}
	}
	if n := p.Nextcloud; n != nil {
		if !nextcloudRe.MatchString(n.URL) || (n.Mode != NextcloudClient && n.Mode != NextcloudDrive) {
			return Fail(ErrInvalidMount, n.URL)
		}
	}
	for _, rule := range p.ScreenTime {
		if !ValidUser(rule.User) {
			return Fail(ErrInvalidUser, rule.User)
		}
		if len(rule.Windows) > maxRuleWindows {
			return Fail(ErrPolicyTooLarge, strconv.Itoa(maxPolicyBytes>>10))
		}
		for _, window := range rule.Windows {
			if err := checkTimeWindow(window); err != nil {
				return err
			}
		}
	}
	// A single policy can contradict itself just as two can.
	if _, conflicts := MergePolicies(map[string]Policy{"": p}); len(conflicts) > 0 {
		return Fail(ErrPolicyConflict, conflicts[0].Item)
	}
	if hasDuplicates(p) {
		return Fail(ErrPolicyConflict, "duplicate entry")
	}
	return nil
}

// UserWritable are the places a person can put a program into, or bring one in.
var UserWritable = []string{"/home/", "/var/home/", "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/media/", "/run/media/", "/mnt/"}

// InUserWritable says whether a person decides what is at a path. Such a path means
// nothing to a rule, and following a link there would let them write the rule.
func InUserWritable(path string) bool {
	return slices.ContainsFunc(UserWritable, func(dir string) bool { return strings.HasPrefix(path, dir) })
}

// SafeProgramPath accepts what can stand in a rule file, whose fields end at a space.
func SafeProgramPath(path string) bool {
	return commandRe.MatchString(path) && !strings.Contains(path, "..")
}

// These values go into the rule file of a daemon that decides on every program.
func checkAppRule(r AppRule) error {
	if !ValidUser(r.User) {
		return Fail(ErrInvalidUser, r.User)
	}
	lists := [][]string{r.ForbiddenPrograms, r.AllowedApps}
	if r.Flatpaks != nil {
		lists = append(lists, r.Flatpaks.Apps)
		if r.Flatpaks.Mode != FlatpakAllow && r.Flatpaks.Mode != FlatpakDeny {
			return Fail(ErrInvalidAppRule, r.Flatpaks.Mode)
		}
	}
	for _, list := range lists {
		if len(list) > maxPolicyPackages {
			return Fail(ErrPolicyTooLarge, strconv.Itoa(maxPolicyBytes>>10))
		}
	}
	for _, program := range r.ForbiddenPrograms {
		if !SafeProgramPath(program) || InUserWritable(program) {
			return Fail(ErrInvalidAppRule, program)
		}
	}
	// Taken together, that would allow only what it meant to deny.
	if r.Strict && r.Flatpaks != nil && r.Flatpaks.Mode == FlatpakDeny {
		return Fail(ErrInvalidAppRule, r.Flatpaks.Mode)
	}
	for _, app := range r.AllowedApps {
		if !appIDRe.MatchString(app) {
			return Fail(ErrInvalidAppRule, app)
		}
	}
	if r.Flatpaks != nil {
		for _, app := range r.Flatpaks.Apps {
			if !appIDRe.MatchString(app) {
				return Fail(ErrInvalidAppRule, app)
			}
		}
	}
	return nil
}

// These values end up in a configuration file of a daemon running as root, so a
// line break must not be able to add settings. Only TLS is accepted, because the
// passwords of everyone go over this connection.
func checkDirectory(d DirectoryRule) error {
	if !ldapURIRe.MatchString(d.URI) {
		return Fail(ErrInvalidDirectory, "uri")
	}
	if !distinguishedRe.MatchString(d.BaseDN) || !distinguishedRe.MatchString(d.BindDN) {
		return Fail(ErrInvalidDirectory, "dn")
	}
	if d.BindPassword == "" || d.BindPassword != strings.TrimSpace(d.BindPassword) || !ValidText(d.BindPassword, maxBindPassword) {
		return Fail(ErrInvalidDirectory, "password")
	}
	if !singleCertificate(d.CA) {
		return Fail(ErrInvalidDirectory, "ca")
	}
	return nil
}

func hasDuplicates(p Policy) bool {
	paths := map[string]bool{}
	for _, file := range p.Files {
		if paths[file.Path] {
			return true
		}
		paths[file.Path] = true
	}
	names := map[string]bool{}
	for _, ca := range p.CAs {
		if names[ca.Name] {
			return true
		}
		names[ca.Name] = true
	}
	folders := map[string]bool{}
	for _, mount := range p.Mounts {
		if folders[mount.Folder] {
			return true
		}
		folders[mount.Folder] = true
	}
	appUsers := map[string]bool{}
	for _, rule := range p.Apps {
		if appUsers[rule.User] {
			return true
		}
		appUsers[rule.User] = true
	}
	users := map[string]bool{}
	for _, rule := range p.ScreenTime {
		if users[rule.User] {
			return true
		}
		users[rule.User] = true
	}
	return false
}

func checkTimeWindow(w Window) error {
	if len(w.Days) == 0 {
		return Fail(ErrInvalidWindow, "no days")
	}
	for _, day := range w.Days {
		if _, ok := weekday[day]; !ok {
			return Fail(ErrInvalidWindow, day)
		}
	}
	if !clockRe.MatchString(w.Start) || !clockRe.MatchString(w.End) || w.Start >= w.End {
		return Fail(ErrInvalidWindow, w.Start+"-"+w.End)
	}
	return nil
}

// Contains says whether a moment in the given zone lies inside the window.
func (w Window) Contains(t time.Time) bool {
	_, _, ok := w.Bounds(t)
	return ok
}

// Bounds returns the start and end of the window on the day of t, and whether t
// lies inside. It is built from the wall clock, so a daylight saving change does
// not shift a window.
func (w Window) Bounds(t time.Time) (start, end time.Time, inside bool) {
	if !slices.ContainsFunc(w.Days, func(day string) bool { return weekday[day] == t.Weekday() }) {
		return time.Time{}, time.Time{}, false
	}
	start, end = w.at(t, w.Start), w.at(t, w.End)
	return start, end, !t.Before(start) && t.Before(end)
}

func (w Window) at(t time.Time, clock string) time.Time {
	hours, _ := strconv.Atoi(clock[:2])
	minutes, _ := strconv.Atoi(clock[3:])
	return time.Date(t.Year(), t.Month(), t.Day(), hours, minutes, 0, 0, t.Location())
}

// Hash identifies a policy. All sides compute it from the typed value, so
// neither whitespace nor field order changes it.
func (p Policy) Hash() string {
	raw, err := json.Marshal(p)
	if err != nil {
		panic(err) // a struct of strings and slices always encodes
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ValidAppID says whether a launcher can be named in a rule.
func ValidAppID(id string) bool { return appIDRe.MatchString(id) }

// IsZero says whether a policy asks for nothing.
func (p Policy) IsZero() bool { return p.Hash() == (Policy{}).Hash() }

// merger collects where each entry came from, for naming conflicts.
type merger struct {
	conflicts map[string]map[string]bool
}

func (m *merger) conflict(item string, groups ...string) {
	if m.conflicts[item] == nil {
		m.conflicts[item] = map[string]bool{}
	}
	for _, group := range groups {
		m.conflicts[item][group] = true
	}
}

// keyed merges entries that have to agree when they share a key.
func keyed[T any](m *merger, label string, names []string, groups map[string]Policy, list func(Policy) []T, key func(T) string) []T {
	seen := map[string]T{}
	from := map[string]string{}
	for _, name := range names {
		for _, entry := range list(groups[name]) {
			k := key(entry)
			if earlier, ok := seen[k]; ok {
				if !reflect.DeepEqual(earlier, entry) {
					m.conflict(label+" "+k, from[k], name)
				}
				continue
			}
			seen[k], from[k] = entry, name
		}
	}
	merged := make([]T, 0, len(seen))
	for _, k := range slices.Sorted(maps.Keys(seen)) {
		merged = append(merged, seen[k])
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

// union merges lists of names. Required and forbidden then get compared.
func union(names []string, groups map[string]Policy, list func(Policy) []string) (merged []string, from map[string]string) {
	from = map[string]string{}
	for _, name := range names {
		for _, entry := range list(groups[name]) {
			if _, ok := from[entry]; !ok {
				from[entry] = name
				merged = append(merged, entry)
			}
		}
	}
	sort.Strings(merged)
	return merged, from
}

// single merges a value that can only have one setting.
func single[T any](m *merger, label string, names []string, groups map[string]Policy, get func(Policy) (T, bool)) (value T, found bool) {
	first := ""
	for _, name := range names {
		next, ok := get(groups[name])
		if !ok {
			continue
		}
		if found && !reflect.DeepEqual(value, next) {
			m.conflict(label, first, name)
			continue
		}
		if !found {
			value, found, first = next, true, name
		}
	}
	return value, found
}

// MergePolicies builds what a device has to keep from the policies of its
// groups, by group name. Rules that add up do so, and a stricter security rule
// wins. Everything else that disagrees is a conflict, because guessing here
// would mean deciding for the admin. The result is always in the same order, so
// that equal policies have equal hashes.
func MergePolicies(groups map[string]Policy) (Policy, []PolicyConflict) {
	names := slices.Sorted(maps.Keys(groups))
	m := &merger{conflicts: map[string]map[string]bool{}}
	var out Policy

	var requiredFrom, forbiddenFrom map[string]string
	out.RequiredPackages, requiredFrom = union(names, groups, func(p Policy) []string { return p.RequiredPackages })
	out.ForbiddenPackages, forbiddenFrom = union(names, groups, func(p Policy) []string { return p.ForbiddenPackages })
	for name, group := range requiredFrom {
		if other, ok := forbiddenFrom[name]; ok {
			m.conflict("package "+name, group, other)
		}
	}
	out.RequiredFlatpaks, requiredFrom = union(names, groups, func(p Policy) []string { return p.RequiredFlatpaks })
	out.ForbiddenFlatpaks, forbiddenFrom = union(names, groups, func(p Policy) []string { return p.ForbiddenFlatpaks })
	for name, group := range requiredFrom {
		if other, ok := forbiddenFrom[name]; ok {
			m.conflict("flatpak "+name, group, other)
		}
	}

	out.Files = keyed(m, "file", names, groups, func(p Policy) []FilePutPayload { return p.Files },
		func(f FilePutPayload) string { return f.Path })
	out.CAs = keyed(m, "CA", names, groups, func(p Policy) []CAInstallPayload { return p.CAs },
		func(c CAInstallPayload) string { return c.Name })
	out.Mounts = keyed(m, "mount", names, groups, func(p Policy) []MountRule { return p.Mounts },
		func(r MountRule) string { return r.Folder })
	out.Apps = keyed(m, "app rule of", names, groups, func(p Policy) []AppRule { return p.Apps },
		func(r AppRule) string { return r.User })
	out.ScreenTime = keyed(m, "screen time of", names, groups, func(p Policy) []ScreenTimeRule { return p.ScreenTime },
		func(r ScreenTimeRule) string { return r.User })

	if rule, ok := single(m, "update rule", names, groups, func(p Policy) (UpdateRule, bool) {
		if p.Updates == nil {
			return UpdateRule{}, false
		}
		return *p.Updates, true
	}); ok {
		out.Updates = &rule
	}
	if rule, ok := single(m, "directory", names, groups, func(p Policy) (DirectoryRule, bool) {
		if p.Directory == nil {
			return DirectoryRule{}, false
		}
		return *p.Directory, true
	}); ok {
		out.Directory = &rule
	}
	if rule, ok := single(m, "Nextcloud", names, groups, func(p Policy) (NextcloudRule, bool) {
		if p.Nextcloud == nil {
			return NextcloudRule{}, false
		}
		return *p.Nextcloud, true
	}); ok {
		out.Nextcloud = &rule
	}
	if zone, ok := single(m, "time zone", names, groups, func(p Policy) (string, bool) {
		return p.TimeZone, p.TimeZone != ""
	}); ok {
		out.TimeZone = zone
	}
	for _, name := range names {
		// Nothing depends on this, so the first one does.
		if out.Language == "" {
			out.Language = groups[name].Language
		}
		if rule := groups[name].Security; rule != nil {
			if out.Security == nil {
				out.Security = &SecurityRule{}
			}
			out.Security.Firewall = out.Security.Firewall || rule.Firewall
			out.Security.DiskEncryption = out.Security.DiskEncryption || rule.DiskEncryption
			out.Security.ScreenLock = out.Security.ScreenLock || rule.ScreenLock
		}
	}

	conflicts := make([]PolicyConflict, 0, len(m.conflicts))
	for _, item := range slices.Sorted(maps.Keys(m.conflicts)) {
		conflicts = append(conflicts, PolicyConflict{Item: item, Groups: slices.Sorted(maps.Keys(m.conflicts[item]))})
	}
	return out, conflicts
}
