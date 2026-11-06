package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

const (
	policyFile      = "policy.json"
	policyStateFile = "policy-state.json"
	// policyInterval is how often a device compares itself with its policy. It
	// checks at start as well, so this also bounds how long a change survives.
	policyInterval = 15 * time.Minute
	policyTick     = time.Minute
	// policyRebootDelay is the warning before a reboot in a maintenance window.
	policyRebootDelay = 10
	maxDeviationText  = 200
)

// Kinds of deviation in a report.
const (
	deviationPolicy  = "policy"
	deviationCA      = "ca"
	deviationFile    = "file"
	deviationPackage = "package"
	deviationFlatpak = "flatpak"
	deviationUpdates = "updates"
	deviationScreen  = "screen_time"
	deviationSecure  = "security"
	deviationLogin   = "directory"
	deviationMount   = "mount"
)

// policyState is what the device has to remember besides the policy.
type policyState struct {
	// ManagedCAs are the CAs a policy installed, so that a CA leaves the trust
	// store again when it leaves the policy.
	ManagedCAs []string `json:"managed_cas,omitempty"`
	// LastUpdate is the last start of automatic updates.
	LastUpdate time.Time `json:"last_update,omitzero"`
	// UpdateError says why the last automatic update failed.
	UpdateError string `json:"update_error,omitempty"`
	// Extensions hold how long a user may stay beyond the time windows.
	Extensions map[string]time.Time `json:"extensions,omitempty"`
	// ScreenUIDs remembers who a screen time rule is about, by the name in the rule.
	ScreenUIDs map[string]string `json:"screen_uids,omitempty"`
}

// PolicyEngine keeps a device in the state of its signed policy. Everything it
// needs lives on the device, so it goes on working without the server.
type PolicyEngine struct {
	dir  string
	exec *Executor
	log  *slog.Logger
	wake chan struct{}

	mu     sync.Mutex
	policy *api.Policy
	// broken says why the stored state cannot be read. Enforcement then stops
	// and what is on the device stays: treating that like no policy would remove
	// managed CAs. Screen time cannot go on without its rules, which the report
	// says.
	broken string
	state  policyState
	status api.PolicyStatus

	// screen is what the screen time check remembers about each user. Only the
	// check uses it, so it needs no lock.
	screen map[string]*screenUser
	// screenIssue says why the last screen time check failed.
	screenIssue string
	// screenFresh says that the agent has not looked at the current rules yet.
	// Whoever is logged in then was there first, and gets a lock and a minute.
	screenFresh bool
	// popups counts the warnings on their way, for tests.
	popups sync.WaitGroup
}

// OpenPolicy loads the stored policy. A file that cannot be read shows up as a
// deviation and never stops the agent, because signed tasks are what can fix it.
func OpenPolicy(dir string, exec *Executor, log *slog.Logger) *PolicyEngine {
	pe := &PolicyEngine{dir: dir, exec: exec, log: log, wake: make(chan struct{}, 1), screen: map[string]*screenUser{}, screenFresh: true}
	raw, err := os.ReadFile(filepath.Join(dir, policyFile))
	if err == nil {
		var p api.Policy
		if err = json.Unmarshal(raw, &p); err == nil {
			if err = api.CheckPolicy(p); err == nil {
				pe.policy = &p
			}
		}
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Error("stored policy is unusable", "err", err)
		pe.broken = clip(cleanText(err.Error()), maxDeviationText)
	}
	if raw, err := os.ReadFile(filepath.Join(dir, policyStateFile)); err == nil {
		if err := json.Unmarshal(raw, &pe.state); err != nil {
			// Going on would overwrite the list of managed CAs with nothing.
			log.Error("policy state is unusable", "err", err)
			pe.broken = clip(cleanText(policyStateFile+": "+err.Error()), maxDeviationText)
		}
	}
	return pe
}

func (pe *PolicyEngine) saveState() error {
	raw, err := json.Marshal(pe.state)
	if err != nil {
		return err
	}
	return writeAtomicSync(filepath.Join(pe.dir, policyStateFile), raw, 0o600)
}

// Set replaces the policy. The file comes first: what is not stored would be
// gone at the next start.
func (pe *PolicyEngine) Set(p api.Policy) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := writeAtomicSync(filepath.Join(pe.dir, policyFile), raw, 0o600); err != nil {
		return err
	}
	pe.mu.Lock()
	pe.policy, pe.broken, pe.screenFresh = &p, "", true
	pe.mu.Unlock()
	pe.nudge()
	return nil
}

// Clear ends the policy. What it put on the device stays, except for CAs.
func (pe *PolicyEngine) Clear() error {
	err := os.Remove(filepath.Join(pe.dir, policyFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// The signature that asked for this is used up, so it has to last.
	if err := syncDir(pe.dir); err != nil {
		return err
	}
	pe.mu.Lock()
	pe.policy, pe.broken = nil, ""
	pe.status = api.PolicyStatus{}
	pe.mu.Unlock()
	pe.nudge()
	return nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (pe *PolicyEngine) nudge() {
	select {
	case pe.wake <- struct{}{}:
	default:
	}
}

// Status is the part of a report about the policy, empty without one.
func (pe *PolicyEngine) Status() *api.PolicyStatus {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	if pe.broken != "" {
		return &api.PolicyStatus{Deviations: []api.PolicyDeviation{{Kind: deviationPolicy, Item: policyFile, Detail: pe.broken}}}
	}
	if pe.policy == nil {
		return nil
	}
	status := pe.status
	status.Hash = pe.policy.Hash()
	status.Deviations = slices.Clone(status.Deviations)
	if pe.state.UpdateError != "" {
		status.Deviations = append(status.Deviations, api.PolicyDeviation{Kind: deviationUpdates, Item: "automatic updates", Detail: pe.state.UpdateError})
	}
	if pe.screenIssue != "" {
		status.Deviations = append(status.Deviations, api.PolicyDeviation{Kind: deviationScreen, Item: "screen time", Detail: pe.screenIssue})
	}
	return &status
}

// Loop checks at start, after a new policy and then regularly.
func (pe *PolicyEngine) Loop(ctx context.Context) {
	ticker := time.NewTicker(policyTick)
	defer ticker.Stop()
	next := time.Now()
	for {
		if !time.Now().Before(next) {
			pe.Enforce(ctx)
			next = time.Now().Add(policyInterval)
		}
		pe.runUpdates(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-pe.wake:
			next = time.Now()
		}
	}
}

// outcome collects the result of one check.
type outcome struct {
	deviations []api.PolicyDeviation
	corrected  []string
}

func (o *outcome) deviate(kind, item string, detail any) {
	text := ""
	if detail != nil {
		text = clip(cleanText(fmt.Sprint(detail)), maxDeviationText)
	}
	o.deviations = append(o.deviations, api.PolicyDeviation{Kind: kind, Item: item, Detail: text})
}

// Enforce brings the device to its policy. One entry that fails costs only that
// entry, and it stays in the report until it is resolved.
func (pe *PolicyEngine) Enforce(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, taskTimeout)
	defer cancel()

	pe.mu.Lock()
	broken := pe.broken != ""
	policy := api.Policy{}
	if pe.policy != nil {
		policy = *pe.policy
	}
	pe.mu.Unlock()
	if broken {
		return
	}

	var o outcome
	pe.enforceCAs(ctx, policy.CAs, &o)
	pe.enforceFiles(policy.Files, &o)
	pe.enforcePackages(ctx, policy, &o)
	pe.enforceFlatpaks(ctx, policy, &o)
	checks := pe.enforceSecurity(ctx, policy.Security, &o)
	directory := pe.enforceDirectory(ctx, policy.Directory, policy.Mounts, &o)
	if directory != "" {
		if checks == nil {
			checks = map[string]string{}
		}
		checks["directory"] = directory
	}
	pe.enforceMounts(ctx, policy.Mounts, directory == checkOn, &o)
	pe.enforceNextcloud(ctx, policy.Nextcloud, &o)
	if len(o.corrected) > 0 {
		pe.log.Warn("policy corrected this device", "items", o.corrected)
	}

	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.status = api.PolicyStatus{CheckedAt: time.Now().UTC(), Deviations: o.deviations, Corrected: o.corrected, Checks: checks}
}

func (pe *PolicyEngine) enforceCAs(ctx context.Context, cas []api.CAInstallPayload, o *outcome) {
	e := pe.exec
	if e.Platform.Trust == nil {
		for _, ca := range cas {
			o.deviate(deviationCA, ca.Name, "no supported trust store found")
		}
		return
	}
	wanted := make([]string, 0, len(cas))
	for _, ca := range cas {
		wanted = append(wanted, ca.Name)
	}

	pe.mu.Lock()
	stale := slices.DeleteFunc(slices.Clone(pe.state.ManagedCAs), func(name string) bool { return slices.Contains(wanted, name) })
	// Recorded before the install, so that a crash cannot leave a CA in the
	// store that nothing would ever remove.
	pe.state.ManagedCAs = append(slices.Clone(wanted), stale...)
	err := pe.saveState()
	pe.mu.Unlock()
	if err != nil {
		o.deviate(deviationCA, "state", err)
		return
	}

	for _, ca := range cas {
		current, err := os.ReadFile(e.caPath(ca.Name))
		if err == nil && bytes.Equal(current, []byte(ca.PEM)) {
			continue
		}
		if out, err := e.caInstall(ctx, ca); err != nil {
			// The file comes first in caInstall. Left behind, it would look
			// like success at the next check, with the store not updated.
			if err := os.Remove(e.caPath(ca.Name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				pe.log.Warn("removing a half installed CA failed", "name", ca.Name, "err", err)
			}
			o.deviate(deviationCA, ca.Name, strings.TrimSpace(out+" "+err.Error()))
			continue
		}
		o.corrected = append(o.corrected, "ca "+ca.Name)
	}

	kept := slices.Clone(wanted)
	for _, name := range stale {
		if err := e.caRemove(ctx, name); err != nil {
			o.deviate(deviationCA, name, err)
			kept = append(kept, name)
			continue
		}
		o.corrected = append(o.corrected, "ca "+name+" removed")
	}
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.state.ManagedCAs = kept
	if err := pe.saveState(); err != nil {
		o.deviate(deviationCA, "state", err)
	}
}

func (e *Executor) caPath(name string) string {
	return filepath.Join(e.path(e.Platform.Trust.Dir), "hauswart-"+name+".crt")
}

// caRemove ends the trust in a CA, in the system store and in browsers.
func (e *Executor) caRemove(ctx context.Context, name string) error {
	if err := os.Remove(e.caPath(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	argv := e.Platform.Trust.Update
	if out, err := e.Run(ctx, argv[0], argv[1:]...); err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	if e.Platform.Trust.Browsers {
		return e.untrustInBrowsers(name)
	}
	return nil
}

func (pe *PolicyEngine) enforceFiles(files []api.FilePutPayload, o *outcome) {
	for _, file := range files {
		if pe.exec.fileMatches(file) {
			continue
		}
		if _, err := pe.exec.filePut(file); err != nil {
			o.deviate(deviationFile, file.Path, err)
			continue
		}
		o.corrected = append(o.corrected, "file "+file.Path)
	}
}

// fileMatches looks at the link itself, as a link cannot be what was asked for.
func (e *Executor) fileMatches(p api.FilePutPayload) bool {
	full := e.path(filepath.Clean(p.Path))
	info, err := os.Lstat(full)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	mode := uint64(0o644)
	if p.Mode != "" {
		if mode, err = strconv.ParseUint(p.Mode, 8, 32); err != nil {
			return false
		}
	}
	if uint64(info.Mode().Perm()) != mode {
		return false
	}
	current, err := os.ReadFile(full)
	return err == nil && bytes.Equal(current, []byte(p.Content))
}

// presence tells which of some names are on the device.
type presence func(ctx context.Context, names []string) (map[string]bool, error)

// converge applies a change to the names that need it, all at once first, as
// that is much faster. A package manager refuses a whole batch for one unknown
// name, so a failed batch is repeated name by name. Only a second look at the
// device counts: a package manager may well succeed and change nothing.
func converge(ctx context.Context, o *outcome, kind string, names []string, wanted bool, look presence, apply func(context.Context, []string) (string, error)) {
	if len(names) == 0 {
		return
	}
	found, err := look(ctx, names)
	if err != nil {
		for _, name := range names {
			o.deviate(kind, name, err)
		}
		return
	}
	pending := slices.DeleteFunc(slices.Clone(names), func(name string) bool { return found[name] == wanted })
	if len(pending) == 0 {
		return
	}
	reasons := map[string]string{}
	if out, err := apply(ctx, pending); err != nil {
		reasons[pending[0]] = strings.TrimSpace(out + " " + err.Error())
		if len(pending) > 1 {
			for _, name := range pending {
				if out, err := apply(ctx, []string{name}); err != nil {
					reasons[name] = strings.TrimSpace(out + " " + err.Error())
				} else {
					delete(reasons, name)
				}
			}
		}
	}
	found, err = look(ctx, pending)
	for _, name := range pending {
		switch {
		case err != nil:
			o.deviate(kind, name, err)
		case found[name] == wanted:
			o.corrected = append(o.corrected, kind+" "+name)
		case reasons[name] != "":
			o.deviate(kind, name, reasons[name])
		case wanted:
			o.deviate(kind, name, "still not installed")
		default:
			o.deviate(kind, name, "still installed")
		}
	}
}

func (pe *PolicyEngine) enforcePackages(ctx context.Context, p api.Policy, o *outcome) {
	e := pe.exec
	if e.Platform.Backend == nil {
		for _, name := range slices.Concat(p.RequiredPackages, p.ForbiddenPackages) {
			o.deviate(deviationPackage, name, "no supported package manager found")
		}
		return
	}
	// Forbidden first: what is required may conflict with what has to go.
	converge(ctx, o, deviationPackage, p.ForbiddenPackages, false, e.installedPackages, func(ctx context.Context, names []string) (string, error) {
		return e.packages(ctx, api.TaskPkgRemove, names)
	})
	converge(ctx, o, deviationPackage, p.RequiredPackages, true, e.installedPackages, func(ctx context.Context, names []string) (string, error) {
		return e.packages(ctx, api.TaskPkgInstall, names)
	})
}

func (e *Executor) installedPackages(ctx context.Context, names []string) (map[string]bool, error) {
	backend := e.Platform.Backend
	found := make(map[string]bool, len(names))
	for _, name := range names {
		argv := backend.Query(name)
		out, err := e.Run(ctx, argv[0], argv[1:]...)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		found[name] = backend.Present(out, err)
	}
	return found, nil
}

func (pe *PolicyEngine) enforceFlatpaks(ctx context.Context, p api.Policy, o *outcome) {
	e := pe.exec
	if !e.flatpakInstalled() {
		// Nothing can be installed, and so nothing forbidden can be there.
		for _, name := range p.RequiredFlatpaks {
			o.deviate(deviationFlatpak, name, "flatpak is not installed")
		}
		return
	}
	converge(ctx, o, deviationFlatpak, p.ForbiddenFlatpaks, false, e.installedFlatpaks, e.flatpakRemove)
	converge(ctx, o, deviationFlatpak, p.RequiredFlatpaks, true, e.installedFlatpaks, func(ctx context.Context, names []string) (string, error) {
		return e.packages(ctx, api.TaskFlatpakInstall, names)
	})
}

func (e *Executor) flatpakInstalled() bool {
	return e.Platform.Flatpak || (e.Has != nil && e.Has("flatpak"))
}

func (e *Executor) installedFlatpaks(ctx context.Context, names []string) (map[string]bool, error) {
	out, err := e.Run(ctx, "flatpak", "list", "--system", "--app", "--columns=application")
	if err != nil {
		return nil, fmt.Errorf("flatpak list: %w: %s", err, out)
	}
	apps := strings.Fields(out)
	found := make(map[string]bool, len(names))
	for _, name := range names {
		found[name] = slices.Contains(apps, name)
	}
	return found, nil
}

func (e *Executor) flatpakRemove(ctx context.Context, names []string) (string, error) {
	defer e.lockPackages()()
	return e.Run(ctx, "flatpak", append([]string{"uninstall", "--system", "--noninteractive", "-y", "--"}, names...)...)
}

// runUpdates starts automatic updates once per maintenance window. A window a
// device was off for is not made up for: nobody expects a reboot at another
// time. The start is stored first, so that a crash or a reboot in the window
// cannot start the same run again.
func (pe *PolicyEngine) runUpdates(ctx context.Context, now time.Time) {
	pe.mu.Lock()
	if pe.policy == nil || pe.policy.Updates == nil {
		pe.mu.Unlock()
		return
	}
	rule := *pe.policy.Updates
	local := now.In(zoneOf(*pe.policy))
	start, _, inside := rule.Window.Bounds(local)
	if !inside || !pe.state.LastUpdate.Before(start) {
		pe.mu.Unlock()
		return
	}
	pe.state.LastUpdate = now
	err := pe.saveState()
	pe.mu.Unlock()
	if err != nil {
		pe.log.Error("saving the update state failed, skipping this window", "err", err)
		return
	}

	ctx, cancel := context.WithTimeout(ctx, taskTimeout)
	defer cancel()
	pe.log.Info("maintenance window started")
	err = pe.exec.applyUpdates(ctx, rule, now)
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.state.UpdateError = ""
	if err != nil {
		pe.log.Warn("automatic updates failed", "err", err)
		pe.state.UpdateError = clip(cleanText(err.Error()), maxDeviationText)
	}
	if err := pe.saveState(); err != nil {
		pe.log.Error("saving the update state failed", "err", err)
	}
}

func zoneOf(p api.Policy) *time.Location {
	if p.TimeZone != "" {
		// CheckPolicy accepted it, and the zone data is part of the binary.
		if zone, err := time.LoadLocation(p.TimeZone); err == nil {
			return zone
		}
	}
	return time.Local
}

func (e *Executor) applyUpdates(ctx context.Context, rule api.UpdateRule, now time.Time) error {
	if err := e.checkUpdates(ctx); err != nil {
		return err
	}
	if e.pendingUpdates() > 0 {
		if out, err := e.packages(ctx, api.TaskPkgUpgrade, nil); err != nil {
			return fmt.Errorf("%w: %s", err, clip(out, maxDeviationText))
		}
		if err := e.checkUpdates(ctx); err != nil {
			return err
		}
	}
	if rule.Reboot != api.RebootWindow || !e.rebootNeeded() {
		return nil
	}
	_, err := e.power(ctx, "-r", "restart", api.PowerPayload{
		DelayMinutes: policyRebootDelay,
		Message:      "Updates are finished.",
		ExpiresAt:    now.Add(time.Hour),
	})
	return err
}

func (e *Executor) pendingUpdates() int {
	e.insight.mu.Lock()
	defer e.insight.mu.Unlock()
	if e.insight.updates == nil {
		return 0
	}
	return e.insight.updates.Pending
}

func (e *Executor) rebootNeeded() bool {
	e.insight.mu.Lock()
	defer e.insight.mu.Unlock()
	return e.insight.updates != nil && e.insight.updates.Reboot == api.RebootRequired
}

// setPolicy is only reachable through the guard. A device without pinned keys
// has no way to tell a policy from what a hacked server made up, and a policy
// installs software and trusts CAs on its own, again and again.
func (a *Agent) setPolicy(task api.Task) api.TaskResult {
	if a.guard == nil {
		return api.TaskResult{OK: false, Output: "policies need pinned signing keys on this device"}
	}
	if err := api.Validate(task.Type, task.Payload); err != nil {
		return api.TaskResult{OK: false, Output: err.Error()}
	}
	if task.Type == api.TaskPolicyClear {
		if err := a.policy.Clear(); err != nil {
			return api.TaskResult{OK: false, Output: err.Error()}
		}
		return api.TaskResult{OK: true, Output: "policy removed"}
	}
	var p api.Policy
	if err := json.Unmarshal(task.Payload, &p); err != nil {
		return api.TaskResult{OK: false, Output: err.Error()}
	}
	if err := a.policy.Set(p); err != nil {
		return api.TaskResult{OK: false, Output: err.Error()}
	}
	return api.TaskResult{OK: true, Output: "policy " + p.Hash()[:12] + " stored, the device applies it now"}
}
