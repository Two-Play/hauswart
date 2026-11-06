package agent

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

const (
	updateInterval = 6 * time.Hour
	updateRetry    = 30 * time.Minute
	updateTick     = 30 * time.Second
	updateTimeout  = 5 * time.Minute
	maxUpdateError = 300
	// pacman keeps its own copy of the sync databases here. Refreshing the real
	// ones without upgrading would set up a partial upgrade, which Arch does
	// not support.
	pacmanCheckDB = "/var/cache/hauswart/pacman"
)

// insightState is what the agent remembers between reports.
type insightState struct {
	// pkg keeps update checks apart from package tasks, because package managers
	// refuse to run twice.
	pkg sync.Mutex

	mu      sync.Mutex
	sudo    sudoScan
	updates *api.UpdateStatus
	// stale says that a package task ran since the last check.
	stale bool
}

// lockPackages reserves the package manager. The returned function releases it
// and asks for a new update check, as the result is out of date by then.
func (e *Executor) lockPackages() func() {
	e.insight.pkg.Lock()
	return func() {
		e.insight.mu.Lock()
		e.insight.stale = true
		e.insight.mu.Unlock()
		e.insight.pkg.Unlock()
	}
}

// collectInsight builds the part of a report that needs more than /proc.
func (e *Executor) collectInsight(ctx context.Context) api.Insight {
	insight := api.Insight{Accounts: e.accounts(ctx)}
	e.insight.mu.Lock()
	defer e.insight.mu.Unlock()
	insight.Updates = e.insight.updates
	return insight
}

// updateLoop checks at start and then a few times a day, because a check uses
// the network. A package task asks for a check straight away.
func (a *Agent) updateLoop(ctx context.Context) {
	next := time.Now()
	ticker := time.NewTicker(updateTick)
	defer ticker.Stop()
	for {
		if a.exec.updateCheckDue() || !time.Now().Before(next) {
			if err := a.exec.checkUpdates(ctx); err != nil {
				a.log.Warn("update check failed", "err", err)
				next = time.Now().Add(updateRetry)
			} else {
				next = time.Now().Add(updateInterval)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (e *Executor) updateCheckDue() bool {
	e.insight.mu.Lock()
	defer e.insight.mu.Unlock()
	return e.insight.stale
}

// checkUpdates refreshes the update status. The error is also part of the
// status, and what the last good check found stays.
func (e *Executor) checkUpdates(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	e.insight.pkg.Lock()
	defer e.insight.pkg.Unlock()
	e.insight.mu.Lock()
	e.insight.stale = false
	status := api.UpdateStatus{}
	if e.insight.updates != nil {
		status = *e.insight.updates
	}
	e.insight.mu.Unlock()

	var err error
	if e.Platform.Backend == nil {
		err = errors.New("no supported package manager found")
	} else if check, ok := updateChecks[e.Platform.Backend.Name]; !ok {
		err = fmt.Errorf("no update check for %s", e.Platform.Backend.Name)
	} else {
		var names []string
		if names, err = check(e, ctx); err == nil {
			now := time.Now().UTC()
			status.CheckedAt = &now
			status.Pending = len(names)
			status.Packages = names[:min(len(names), api.MaxUpdateNames)]
		}
	}
	status.Error = ""
	if err != nil {
		status.Error = clip(cleanText(err.Error()), maxUpdateError)
	}
	status.Reboot = e.rebootState(ctx)

	e.insight.mu.Lock()
	e.insight.updates = &status
	e.insight.mu.Unlock()
	return err
}

// updateChecks lists what is pending, in the terms of what pkg.upgrade would do.
var updateChecks = map[string]func(*Executor, context.Context) ([]string, error){
	"dnf5":       dnfCheck("dnf5"),
	"dnf":        dnfCheck("dnf"),
	"apt":        (*Executor).aptCheck,
	"zypper":     (*Executor).zypperCheck,
	"pacman":     (*Executor).pacmanCheck,
	"rpm-ostree": (*Executor).ostreeCheck,
}

func dnfCheck(name string) func(*Executor, context.Context) ([]string, error) {
	return func(e *Executor, ctx context.Context) ([]string, error) {
		out, err := e.Run(ctx, name, "repoquery", "--upgrades", "--quiet", "--qf", `%{name}.%{arch}\n`)
		if err != nil {
			return nil, fmt.Errorf("%s: %w: %s", name, err, clip(out, maxUpdateError))
		}
		return parseDnfUpgrades(out), nil
	}
}

var dnfPackageRe = regexp.MustCompile(`^[A-Za-z0-9._+-]+\.[a-z0-9_]+$`)

// parseDnfUpgrades skips what is not a package, as stderr is part of the
// output, and repoquery may list a package once per available version.
func parseDnfUpgrades(out string) []string {
	names := []string{}
	for line := range strings.Lines(out) {
		if name := strings.TrimSpace(line); dnfPackageRe.MatchString(name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

func (e *Executor) aptCheck(ctx context.Context) ([]string, error) {
	if out, err := e.Run(ctx, "apt-get", "update", "-qq"); err != nil {
		return nil, fmt.Errorf("apt-get update: %w: %s", err, clip(out, maxUpdateError))
	}
	out, err := e.Run(ctx, "apt-get", "--simulate", "upgrade")
	if err != nil {
		return nil, fmt.Errorf("apt-get upgrade: %w: %s", err, clip(out, maxUpdateError))
	}
	return parseAptSimulation(out), nil
}

func parseAptSimulation(out string) []string {
	names := []string{}
	for line := range strings.Lines(out) {
		if rest, ok := strings.CutPrefix(line, "Inst "); ok {
			if fields := strings.Fields(rest); len(fields) > 0 {
				names = append(names, fields[0])
			}
		}
	}
	return names
}

func (e *Executor) zypperCheck(ctx context.Context) ([]string, error) {
	out, err := e.Run(ctx, "zypper", "--non-interactive", "--xmlout", "list-updates")
	if err != nil {
		return nil, fmt.Errorf("zypper: %w: %s", err, clip(out, maxUpdateError))
	}
	return parseZypperUpdates(out), nil
}

var (
	zypperUpdateRe = regexp.MustCompile(`<update\s[^>]*>`)
	zypperNameRe   = regexp.MustCompile(`\sname="([^"]+)"`)
)

func parseZypperUpdates(out string) []string {
	names := []string{}
	for _, tag := range zypperUpdateRe.FindAllString(out, -1) {
		if !strings.Contains(tag, `kind="package"`) {
			continue
		}
		if name := zypperNameRe.FindStringSubmatch(tag); name != nil {
			names = append(names, name[1])
		}
	}
	return names
}

// pacmanCheck does what checkupdates from pacman-contrib does, which is not
// installed by default.
func (e *Executor) pacmanCheck(ctx context.Context) ([]string, error) {
	dbPath := e.path(pacmanCheckDB)
	// pacman downloads as an unprivileged user, who has to reach this directory.
	// It holds only what the repositories publish.
	if err := os.MkdirAll(dbPath, 0o755); err != nil {
		return nil, err
	}
	local := filepath.Join(dbPath, "local")
	if _, err := os.Lstat(local); errors.Is(err, os.ErrNotExist) {
		if err := os.Symlink("/var/lib/pacman/local", local); err != nil {
			return nil, err
		}
	}
	if out, err := e.Run(ctx, "pacman", "-Sy", "--dbpath", dbPath, "--logfile", "/dev/null"); err != nil {
		return nil, fmt.Errorf("pacman: %w: %s", err, clip(out, maxUpdateError))
	}
	// pacman exits with an error if there is nothing to upgrade.
	out, _ := e.Run(ctx, "pacman", "-Qu", "--dbpath", dbPath)
	return parsePacmanUpgrades(out), nil
}

func parsePacmanUpgrades(out string) []string {
	names := []string{}
	for line := range strings.Lines(out) {
		if fields := strings.Fields(line); len(fields) >= 4 && fields[2] == "->" {
			names = append(names, fields[0])
		}
	}
	return names
}

func (e *Executor) ostreeCheck(ctx context.Context) ([]string, error) {
	// rpm-ostree exits with 77 if there is no update.
	out, err := e.Run(ctx, "rpm-ostree", "upgrade", "--preview")
	if err != nil && !strings.Contains(out, "No updates available") && !strings.Contains(out, "No change") {
		return nil, fmt.Errorf("rpm-ostree: %w: %s", err, clip(out, maxUpdateError))
	}
	status, err := e.Run(ctx, "rpm-ostree", "status", "--json")
	if err != nil {
		return nil, fmt.Errorf("rpm-ostree: %w: %s", err, clip(status, maxUpdateError))
	}
	return parseOstreeUpdates(status)
}

type ostreeStatus struct {
	Deployments []struct {
		Booted bool `json:"booted"`
	} `json:"deployments"`
	CachedUpdate *struct {
		Version string `json:"version"`
		RPMDiff struct {
			Upgraded []json.RawMessage `json:"upgraded"`
			Added    []json.RawMessage `json:"added"`
		} `json:"rpm-diff"`
	} `json:"cached-update"`
}

// parseOstreeUpdates reads the cached update. A system that follows a container
// image, like Fedora CoreOS, knows only about layers and a new version, so the
// whole image then counts as one update. Otherwise there is a diff with entries
// that are arrays starting with the package name.
func parseOstreeUpdates(status string) ([]string, error) {
	var parsed ostreeStatus
	if err := json.Unmarshal([]byte(status), &parsed); err != nil {
		return nil, fmt.Errorf("rpm-ostree status: %w", err)
	}
	names := []string{}
	if parsed.CachedUpdate == nil {
		return names, nil
	}
	diff := parsed.CachedUpdate.RPMDiff
	for _, entry := range slices.Concat(diff.Upgraded, diff.Added) {
		var fields []json.RawMessage
		var name string
		if json.Unmarshal(entry, &fields) == nil && len(fields) > 0 && json.Unmarshal(fields[0], &name) == nil {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		names = append(names, cmp.Or(parsed.CachedUpdate.Version, "new image"))
	}
	return names, nil
}

// rebootState combines what the package manager knows with a look at the
// kernels, which is the one thing that always needs a reboot. It says unknown
// rather than no if it has nothing to go on, as in a container.
func (e *Executor) rebootState(ctx context.Context) string {
	hint := e.rebootHint(ctx)
	kernel := e.kernelRebootState()
	switch {
	case hint == api.RebootRequired || kernel == api.RebootRequired:
		return api.RebootRequired
	case hint == api.RebootNotRequired || kernel == api.RebootNotRequired:
		return api.RebootNotRequired
	}
	return api.RebootUnknown
}

func (e *Executor) rebootHint(ctx context.Context) string {
	if _, err := os.Stat(e.path("/run/reboot-required")); err == nil {
		return api.RebootRequired
	}
	if e.Platform.Backend == nil {
		return api.RebootUnknown
	}
	switch name := e.Platform.Backend.Name; name {
	case "dnf5", "dnf":
		out, _ := e.Run(ctx, name, "needs-restarting", "--reboothint")
		return rebootFromText(out, "Reboot is required", "Reboot should not be necessary")
	case "zypper":
		out, _ := e.Run(ctx, "zypper", "needs-rebooting")
		return rebootFromText(out, "Reboot is suggested", "Reboot is probably not necessary")
	case "rpm-ostree":
		out, err := e.Run(ctx, "rpm-ostree", "status", "--json")
		if err != nil {
			return api.RebootUnknown
		}
		return ostreeReboot(out)
	}
	return api.RebootUnknown
}

// rebootFromText goes by the wording, because the exit codes also stand for
// errors such as a missing plugin.
func rebootFromText(out, required, notRequired string) string {
	switch {
	case strings.Contains(out, required):
		return api.RebootRequired
	case strings.Contains(out, notRequired):
		return api.RebootNotRequired
	}
	return api.RebootUnknown
}

// ostreeReboot says that a reboot is due if the newest deployment is not the
// booted one. Deployments are ordered with the default first.
func ostreeReboot(status string) string {
	var parsed ostreeStatus
	if err := json.Unmarshal([]byte(status), &parsed); err != nil || len(parsed.Deployments) == 0 {
		return api.RebootUnknown
	}
	if parsed.Deployments[0].Booted {
		return api.RebootNotRequired
	}
	return api.RebootRequired
}

// kernelRebootState compares the running kernel with the installed ones. A
// system without any, such as a container, gives no answer.
func (e *Executor) kernelRebootState() string {
	raw, err := os.ReadFile(e.path("/proc/sys/kernel/osrelease"))
	if err != nil {
		return api.RebootUnknown
	}
	running := strings.TrimSpace(string(raw))
	base := e.path("/usr/lib/modules")
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) == 0 {
		return api.RebootUnknown
	}
	current, err := os.Stat(filepath.Join(base, running))
	if err != nil {
		return api.RebootRequired
	}
	for _, entry := range entries {
		if info, err := entry.Info(); err == nil && info.IsDir() && info.ModTime().After(current.ModTime()) {
			return api.RebootRequired
		}
	}
	return api.RebootNotRequired
}
