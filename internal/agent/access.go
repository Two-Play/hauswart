package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

const (
	accessFile = "access.json"
	// accessTick is how soon an unlocked screen is locked again.
	accessTick = 5 * time.Second
	// accessGrace is the warning before refused logins end running sessions.
	accessGrace = time.Minute
	// nologinFile makes pam_nologin refuse everyone but root.
	nologinFile = "/run/nologin"
	nologinText = "Hauswart refuses logins on this device for now.\n"
)

// Access blocks a device for some or all of its ordinary accounts, until it is
// lifted or its end has come. The device keeps to it without the server, and
// a restart does not lift it.
type Access struct {
	exec    *Executor
	notices *Notices
	log     *slog.Logger
	path    string
	now     func() time.Time

	mu    sync.Mutex
	block api.AccessPayload
	// grace says until when the sessions of a user ID may run. Only those who
	// were logged in when logins were refused get it.
	grace map[string]time.Time
	// fresh says that the next check gives running sessions their grace.
	fresh bool
	// shown says that the full-screen block may be running, and returnTo is the
	// console that was in front before it.
	shown    bool
	returnTo string
	// checking keeps checks from overlapping.
	checking sync.Mutex
	// screen says who is behind the block for their screen time, nil without
	// screen time.
	screen screenSource
	// blockedFor is whose screen time the block shows, empty for an access block.
	blockedFor string
	// ready says that the block can run for screen time, preparing that it is
	// being set up: cage may have to be installed first.
	ready, preparing bool
}

// screenSource is the part of the policy engine the block needs.
type screenSource interface {
	ScreenBlocks() []api.BlockState
	screenBlocked(user string) bool
}

func OpenAccess(dir string, exec *Executor, notices *Notices, log *slog.Logger) *Access {
	a := &Access{exec: exec, notices: notices, log: log, path: dir + "/" + accessFile, now: time.Now, grace: map[string]time.Time{}}
	raw, err := os.ReadFile(a.path)
	if err == nil {
		err = json.Unmarshal(raw, &a.block)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		// A broken file must not open what was blocked: everyone stays out
		// until an admin opens the device again.
		log.Error("the access file is broken, refusing logins until access is set again", "err", err)
		a.block = api.AccessPayload{Mode: api.AccessLogin}
	}
	a.fresh = true
	// A block from before a restart may still run, so the first check looks.
	a.shown = true
	return a
}

func (a *Access) activeLocked(now time.Time) bool {
	return (a.block.Mode == api.AccessScreen || a.block.Mode == api.AccessLogin || a.block.Mode == api.AccessFullscreen) &&
		(a.block.Until.IsZero() || now.Before(a.block.Until))
}

// Current returns the block in force, for the report.
func (a *Access) Current() *api.AccessPayload {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.activeLocked(a.now()) {
		return nil
	}
	block := a.block
	return &block
}

// StatusFor says how a person is blocked, nil if not at all.
func (a *Access) StatusFor(user string) *api.AccessStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.activeLocked(a.now()) || !affects(a.block, user) {
		return nil
	}
	return &api.AccessStatus{Mode: a.block.Mode, Until: a.block.Until}
}

func affects(block api.AccessPayload, user string) bool {
	return len(block.Users) == 0 || slices.Contains(block.Users, user)
}

func (a *Access) saveLocked() error {
	raw, err := json.Marshal(a.block)
	if err != nil {
		return err
	}
	return writeAtomicSync(a.path, raw, 0o600)
}

// Set takes a new block, or lifts the one in force, and applies it at once.
func (a *Access) Set(ctx context.Context, task api.Task) api.TaskResult {
	if err := api.Validate(task.Type, task.Payload); err != nil {
		return api.TaskResult{OK: false, Output: err.Error()}
	}
	var p api.AccessPayload
	if err := json.Unmarshal(task.Payload, &p); err != nil {
		return api.TaskResult{OK: false, Output: err.Error()}
	}
	if p.Mode == api.AccessFullscreen {
		if err := a.exec.prepareFullscreen(ctx, p); err != nil {
			return api.TaskResult{OK: false, Output: err.Error()}
		}
	}
	a.mu.Lock()
	before := a.block
	if p.Mode == api.AccessOpen {
		a.block = api.AccessPayload{}
	} else {
		a.block = p
	}
	a.grace = map[string]time.Time{}
	a.fresh = true
	if err := a.saveLocked(); err != nil {
		a.block = before
		a.mu.Unlock()
		return api.TaskResult{OK: false, Output: err.Error()}
	}
	a.mu.Unlock()
	// What the block shows changes only once the block itself is saved.
	if p.Mode == api.AccessFullscreen {
		if err := a.exec.writeBlockContent(p); err != nil {
			return api.TaskResult{OK: false, Output: err.Error()}
		}
	}

	if p.Mode == api.AccessOpen {
		a.tell(ctx, before, api.EventAccessOpen)
	} else {
		a.tell(ctx, p, map[string]string{api.AccessScreen: api.EventAccessScreen, api.AccessLogin: api.EventAccessLogin,
			api.AccessFullscreen: api.EventAccessScreen}[p.Mode])
	}
	a.Check(ctx)
	return api.TaskResult{OK: true, Output: describeAccess(p)}
}

func describeAccess(p api.AccessPayload) string {
	if p.Mode == api.AccessOpen {
		return "access is open again"
	}
	who := "everyone with an ordinary account"
	if len(p.Users) > 0 {
		who = strings.Join(p.Users, ", ")
	}
	what := map[string]string{api.AccessScreen: "screen blocked", api.AccessLogin: "logins refused",
		api.AccessFullscreen: "full-screen block"}[p.Mode]
	if p.Until.IsZero() {
		return what + " for " + who + " until access is opened"
	}
	return what + " for " + who + " until " + p.Until.Format(time.RFC3339)
}

// tell records an event for those a block is about.
func (a *Access) tell(ctx context.Context, block api.AccessPayload, kind string) {
	if a.notices == nil || kind == "" {
		return
	}
	urgency := urgencyCritical
	if kind == api.EventAccessOpen {
		urgency = urgencyNormal
	}
	if len(block.Users) == 0 {
		a.notices.record(ctx, api.DeviceEvent{Kind: kind, Until: block.Until}, urgency)
		return
	}
	for _, user := range block.Users {
		a.notices.record(ctx, api.DeviceEvent{Kind: kind, User: user, Until: block.Until}, urgency)
	}
}

// Loop keeps the block until ctx ends.
func (a *Access) Loop(ctx context.Context) {
	ticker := time.NewTicker(accessTick)
	defer ticker.Stop()
	for {
		a.Check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Check ends a block whose time has come, and enforces the one in force.
func (a *Access) Check(ctx context.Context) {
	// One check at a time: a check that read the old block must not undo what
	// Set just did.
	a.checking.Lock()
	defer a.checking.Unlock()
	now := a.now()
	a.mu.Lock()
	var ended api.AccessPayload
	if a.block.Mode != "" && !a.activeLocked(now) {
		ended, a.block = a.block, api.AccessPayload{}
		if err := a.saveLocked(); err != nil {
			a.log.Error("saving the end of a block failed", "err", err)
		}
	}
	block, active, fresh := a.block, a.activeLocked(now), a.fresh
	a.mu.Unlock()
	if ended.Mode != "" {
		a.log.Info("a block ended on time", "mode", ended.Mode)
		a.tell(ctx, ended, api.EventAccessOpen)
	}

	a.syncNologin(active && block.Mode == api.AccessLogin && len(block.Users) == 0)
	a.showOrHide(ctx, active && block.Mode == api.AccessFullscreen, block)
	if !active {
		return
	}
	sessions, err := a.exec.loginSessions(ctx)
	if err != nil {
		a.log.Warn("cannot see the sessions to block", "err", err)
		return
	}
	// Only a check that saw the sessions uses up the grace of a new block.
	a.mu.Lock()
	a.fresh = false
	a.mu.Unlock()
	for uid, session := range sessions {
		if number, _ := strconv.Atoi(uid); number < minUserUID || !affects(block, session.name) {
			continue
		}
		switch block.Mode {
		case api.AccessScreen, api.AccessFullscreen:
			a.lockScreens(ctx, session)
		case api.AccessLogin:
			a.endSessions(ctx, uid, session, fresh, now)
		}
	}
}

// lockScreens locks every graphical session on each check, so that whoever
// unlocks one is locked out again within a few seconds. LockedHint does not
// count: the owner of a session can set it.
func (a *Access) lockScreens(ctx context.Context, session *loginUser) {
	for _, id := range session.ids {
		shown, err := a.exec.Run(ctx, "loginctl", "show-session", id, "-p", "Type")
		if err != nil {
			continue
		}
		props := parseProperties(shown)
		if props["Type"] != "wayland" && props["Type"] != "x11" {
			continue
		}
		if out, err := a.exec.Run(ctx, "loginctl", "lock-session", id); err != nil {
			a.log.Warn("locking a session failed", "user", session.name, "err", err, "output", clip(out, maxDeviationText))
		}
	}
}

// endSessions ends the sessions of someone who may not log in. Who was logged
// in when the block began gets a minute to save, anyone later none.
func (a *Access) endSessions(ctx context.Context, uid string, session *loginUser, fresh bool, now time.Time) {
	a.mu.Lock()
	deadline, known := a.grace[uid]
	if !known && fresh {
		deadline = now.Add(accessGrace)
		a.grace[uid] = deadline
	}
	a.mu.Unlock()
	if !known && fresh {
		if a.notices != nil {
			a.notices.record(ctx, api.DeviceEvent{Kind: api.EventAccessEnding, User: session.name, Until: deadline}, urgencyCritical)
		}
		return
	}
	if known && now.Before(deadline) {
		return
	}
	a.log.Info("ending the sessions of someone who may not log in", "user", session.name)
	if out, err := a.exec.Run(ctx, "loginctl", "terminate-user", session.name); err != nil {
		a.log.Warn("ending sessions failed", "user", session.name, "err", err, "output", clip(out, maxDeviationText))
		return
	}
	a.mu.Lock()
	delete(a.grace, uid)
	a.mu.Unlock()
}

// syncNologin keeps /run/nologin while logins are refused for everyone. It
// leaves a file alone that someone else wrote.
func (a *Access) syncNologin(want bool) {
	path := a.exec.path(nologinFile)
	current, err := os.ReadFile(path)
	ours := err == nil && string(current) == nologinText
	switch {
	case want && !ours && errors.Is(err, os.ErrNotExist):
		if err := os.WriteFile(path, []byte(nologinText), 0o644); err != nil {
			a.log.Error("refusing logins failed", "err", err)
		}
	case !want && ours:
		if err := os.Remove(path); err != nil {
			a.log.Error("allowing logins again failed", "err", err)
		}
	}
}

// showOrHide decides whether the full-screen block covers the screen: for an
// access block, or for someone whose screen time ended, while their session
// is in front. It stays while it is: the console cannot be switched from it.
func (a *Access) showOrHide(ctx context.Context, fullscreen bool, block api.AccessPayload) {
	screenBlocked := a.screen != nil && len(a.screen.ScreenBlocks()) > 0
	if !fullscreen && !screenBlocked {
		a.setBlockedFor("")
		a.hideBlock(ctx)
		return
	}
	front := a.exec.activeUser(ctx)
	switch {
	case fullscreen && (len(block.Users) == 0 || affects(block, front)):
		a.setBlockedFor("")
		a.showBlock(ctx)
	case screenBlocked && front != blockUser && front != "" && a.screen.screenBlocked(front):
		if !a.screenBlockReady(ctx) {
			// Until the block can run, the locked session is all there is.
			return
		}
		a.setBlockedFor(front)
		a.showBlock(ctx)
	case front == blockUser && (fullscreen || a.stillScreenBlocked()):
		// Already in front.
	default:
		a.setBlockedFor("")
		a.hideBlock(ctx)
	}
}

func (a *Access) setBlockedFor(user string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.blockedFor = user
}

// stillScreenBlocked says whether the person the block shows is still behind it.
func (a *Access) stillScreenBlocked() bool {
	a.mu.Lock()
	user := a.blockedFor
	a.mu.Unlock()
	return user != "" && a.screen != nil && a.screen.screenBlocked(user)
}

// BlockState is what the blocker shows now.
func (a *Access) BlockState() api.BlockState {
	a.mu.Lock()
	block, user := a.block, a.blockedFor
	active := a.activeLocked(a.now())
	a.mu.Unlock()
	if user == "" && active && block.Mode == api.AccessFullscreen {
		return api.BlockState{Kind: api.BlockAccess, Message: block.Message}
	}
	if user != "" && a.screen != nil {
		for _, s := range a.screen.ScreenBlocks() {
			if s.User == user {
				return s
			}
		}
	}
	return api.BlockState{Kind: api.BlockAccess}
}

// screenBlockReady sets the block up once for screen time, in the background:
// installing cage takes a while, and the check must not wait for it.
func (a *Access) screenBlockReady(ctx context.Context) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ready || a.preparing {
		return a.ready
	}
	a.preparing = true
	go func() {
		err := a.exec.prepareFullscreen(context.WithoutCancel(ctx), api.AccessPayload{})
		if err == nil {
			err = a.exec.writeBlockContent(api.AccessPayload{})
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		a.preparing = false
		a.ready = err == nil
		if err != nil {
			a.log.Warn("the full-screen block for screen time is not available", "err", err)
		}
	}()
	return false
}
