package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

const (
	// screenTick bounds how long a session outside its time can last.
	screenTick = 15 * time.Second
	// screenGrace is between the lock and the end of a running session.
	screenGrace = time.Minute
	// maxSessionWalk ends the search for the end of a session. A rule can cover
	// the whole week, and then there is no end to find.
	maxSessionWalk = 8 * 24 * time.Hour
)

// screenWarnings are the times before the end at which a user gets a popup,
// longest first.
var screenWarnings = []time.Duration{15 * time.Minute, 5 * time.Minute, time.Minute}

// screenUser is what the check remembers about someone who is logged in.
type screenUser struct {
	// allowed says that the last check found them within their time, which is
	// what earns a warning and a grace period. Someone who logs in outside
	// their time gets neither.
	allowed bool
	// end is the moment the warnings are about, and warned how many were shown.
	end    time.Time
	warned int
	// graceUntil is when a locked session ends.
	graceUntil time.Time
}

var screenTexts = map[string]map[string]string{
	"en": {
		"left":   "%d minute(s) of screen time left. Please save your work.",
		"locked": "Screen time is over. This session ends in a minute.",
		"given":  "You may stay until %s.",
	},
	"de": {
		"left":   "Noch %d Minute(n) Bildschirmzeit. Bitte speichere deine Arbeit.",
		"locked": "Die Bildschirmzeit ist vorbei. Diese Sitzung endet in einer Minute.",
		"given":  "Du darfst bis %s bleiben.",
	},
}

func screenText(language, key string) string {
	if texts, ok := screenTexts[language]; ok {
		return texts[key]
	}
	return screenTexts["en"][key]
}

// sessionEnd says until when a rule lets someone stay, starting from now. Windows
// that touch count as one, also across midnight. The second result is false if
// now is outside all of them.
func sessionEnd(rule api.ScreenTimeRule, now, extension time.Time) (time.Time, bool) {
	end, allowed := now, false
	limit := now.Add(maxSessionWalk)
	for grown := true; grown && end.Before(limit); {
		grown = false
		if extension.After(end) {
			end, allowed, grown = extension, true, true
		}
		for _, window := range rule.Windows {
			if _, until, inside := window.Bounds(end); inside && until.After(end) {
				end, allowed, grown = until, true, true
			}
		}
	}
	return end, allowed
}

// ScreenLoop runs on its own, because a package task in the other loop can take
// minutes and a time window does not wait.
func (pe *PolicyEngine) ScreenLoop(ctx context.Context) {
	ticker := time.NewTicker(screenTick)
	defer ticker.Stop()
	for {
		pe.checkScreenTime(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// loginUser is someone with running sessions, under the name they have now.
type loginUser struct {
	name string
	ids  []string
}

// loginSessions lists the sessions per user ID, of every kind: someone who may not
// be at the desktop may not be on a text console or over SSH either.
func (e *Executor) loginSessions(ctx context.Context) (map[string]*loginUser, error) {
	out, err := e.Run(ctx, "loginctl", "list-sessions", "--no-legend")
	if err != nil {
		return nil, errors.New("loginctl failed, is this a systemd device?")
	}
	sessions := map[string]*loginUser{}
	for line := range strings.Lines(out) {
		fields := strings.Fields(line)
		if len(fields) < 3 || !sessionIDRe.MatchString(fields[0]) {
			continue
		}
		if sessions[fields[1]] == nil {
			sessions[fields[1]] = &loginUser{name: fields[2]}
		}
		sessions[fields[1]].ids = append(sessions[fields[1]].ids, fields[0])
	}
	return sessions, nil
}

// screenAccounts says which user IDs a rule stands for. A rule names a person, and
// a directory account can change its name, while its ID stays. So the ID is
// remembered the first time the name is seen, and a new name does not lead out of
// the rule. The name counts as well: a local account that was created again has a
// new ID, and someone taking over a name is at worst held to that rule.
func (pe *PolicyEngine) screenAccounts(rule api.ScreenTimeRule) []string {
	pe.mu.Lock()
	pinned := pe.state.ScreenUIDs[rule.User]
	pe.mu.Unlock()
	person, err := pe.exec.lookupUser(rule.User)
	if err != nil {
		if pinned == "" {
			return nil
		}
		return []string{pinned}
	}
	if pinned == "" {
		pe.mu.Lock()
		defer pe.mu.Unlock()
		if pe.state.ScreenUIDs == nil {
			pe.state.ScreenUIDs = map[string]string{}
		}
		pe.state.ScreenUIDs[rule.User] = person.Uid
		if err := pe.saveState(); err != nil {
			pe.log.Error("saving the policy state failed", "err", err)
		}
		return []string{person.Uid}
	}
	if pinned == person.Uid {
		return []string{pinned}
	}
	return []string{pinned, person.Uid}
}

func (pe *PolicyEngine) checkScreenTime(ctx context.Context, now time.Time) {
	pe.mu.Lock()
	var rules []api.ScreenTimeRule
	language := ""
	zone := time.Local
	if pe.policy != nil {
		rules, language, zone = pe.policy.ScreenTime, pe.policy.Language, zoneOf(*pe.policy)
	}
	extensions := maps.Clone(pe.state.Extensions)
	fresh := pe.screenFresh
	pe.screenFresh = false
	pe.mu.Unlock()
	if len(rules) == 0 {
		pe.setScreenIssue("")
		return
	}

	sessions, err := pe.exec.loginSessions(ctx)
	if err != nil {
		pe.setScreenIssue(err.Error())
		return
	}
	var issues []string
	local := now.In(zone)
	for _, rule := range rules {
		for _, uid := range pe.screenAccounts(rule) {
			session := sessions[uid]
			if session == nil {
				delete(pe.screen, uid)
				continue
			}
			if number, _ := strconv.Atoi(uid); number < minUserUID {
				continue
			}
			state := pe.screen[uid]
			if state == nil {
				// Without memory of someone, they just logged in. Unless this is
				// the first look at these rules: then they may have been working
				// for hours, and something to save deserves the lock and a minute.
				state = &screenUser{allowed: fresh}
				pe.screen[uid] = state
			}
			extension := extensions[rule.User].In(zone)
			if end, ok := sessionEnd(rule, local, extension); ok {
				pe.warnScreenUser(ctx, session.name, state, language, local, end)
				continue
			}
			if err := pe.endScreenUser(ctx, session.name, session.ids, state, language, now); err != nil {
				issues = append(issues, rule.User+": "+err.Error())
			}
		}
	}
	pe.setScreenIssue(strings.Join(issues, "; "))
}

func (pe *PolicyEngine) setScreenIssue(text string) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.screenIssue = clip(cleanText(text), maxDeviationText)
}

// warnScreenUser shows the most urgent warning that is due. More time resets the
// warnings, because the earlier ones were about another end.
func (pe *PolicyEngine) warnScreenUser(ctx context.Context, user string, state *screenUser, language string, now, end time.Time) {
	state.graceUntil = time.Time{}
	if !state.allowed || !end.Equal(state.end) {
		state.warned = 0
		state.end = end
	}
	state.allowed = true
	left := end.Sub(now)
	due := 0
	for i, before := range screenWarnings {
		if left <= before {
			due = i + 1
		}
	}
	if due <= state.warned {
		return
	}
	state.warned = due
	minutes := int((left + time.Minute - 1) / time.Minute)
	urgency := urgencyNormal
	if due == len(screenWarnings) {
		urgency = urgencyCritical
	}
	pe.popup(ctx, user, fmt.Sprintf(screenText(language, "left"), minutes), urgency)
}

// popup runs apart from the check. It goes through the user's own session, which
// is theirs to slow down, and the end of their time must not wait for that.
func (pe *PolicyEngine) popup(ctx context.Context, user, message, urgency string) {
	pe.popups.Go(func() { pe.exec.popup(context.WithoutCancel(ctx), user, message, urgency) })
}

// endScreenUser locks a session that ran out of time and ends it a minute later.
// Someone who logs in outside their time has nothing to save yet, so that
// session ends right away. The error is what stops it from working.
func (pe *PolicyEngine) endScreenUser(ctx context.Context, user string, ids []string, state *screenUser, language string, now time.Time) error {
	if state.allowed {
		state.allowed = false
		state.graceUntil = now.Add(screenGrace)
		for _, id := range ids {
			if out, err := pe.exec.Run(ctx, "loginctl", "lock-session", id); err != nil {
				pe.log.Warn("locking a session failed", "user", user, "err", err, "output", clip(out, maxDeviationText))
			}
		}
		pe.popup(ctx, user, screenText(language, "locked"), urgencyCritical)
		pe.log.Info("screen time is over", "user", user)
		return nil
	}
	if now.Before(state.graceUntil) {
		return nil
	}
	pe.log.Info("ending the sessions of a user outside their screen time", "user", user)
	if out, err := pe.exec.Run(ctx, "loginctl", "terminate-user", user); err != nil {
		return fmt.Errorf("%w: %s", err, clip(out, maxDeviationText))
	}
	return nil
}

// ScreenStatus says how someone stands with their screen time, nil without a rule.
func (pe *PolicyEngine) ScreenStatus(uid string, now time.Time) *api.ScreenStatus {
	pe.mu.Lock()
	var rules []api.ScreenTimeRule
	zone := time.Local
	if pe.policy != nil {
		rules, zone = pe.policy.ScreenTime, zoneOf(*pe.policy)
	}
	extensions := maps.Clone(pe.state.Extensions)
	pe.mu.Unlock()
	for _, rule := range rules {
		if !slices.Contains(pe.screenAccounts(rule), uid) {
			continue
		}
		end, allowed := sessionEnd(rule, now.In(zone), extensions[rule.User].In(zone))
		status := &api.ScreenStatus{Allowed: allowed}
		if allowed {
			status.Until = end
		}
		return status
	}
	return nil
}

// Extend lets a user stay until a moment today. The device checks this itself,
// because a passkey approval can be for something else than was shown.
func (pe *PolicyEngine) Extend(ctx context.Context, p api.ScreenExtendPayload, now time.Time) (string, error) {
	// Outside the lock: the screen time check needs it, and this may take a while.
	person, personErr := pe.exec.lookupUser(p.User)
	pe.mu.Lock()
	defer pe.mu.Unlock()
	if pe.policy == nil {
		return "", fmt.Errorf("no screen time rule for %s on this device", p.User)
	}
	// The request may come from someone who renamed their account since.
	ruleUser := p.User
	if !slices.ContainsFunc(pe.policy.ScreenTime, func(r api.ScreenTimeRule) bool { return r.User == p.User }) {
		ruleUser = ""
		if personErr == nil {
			for name, uid := range pe.state.ScreenUIDs {
				if uid == person.Uid {
					ruleUser = name
				}
			}
		}
		if ruleUser == "" {
			return "", fmt.Errorf("no screen time rule for %s on this device", p.User)
		}
	}
	if !now.Before(p.Until) {
		return "", errors.New("this extension has already ended")
	}
	if p.Until.Sub(now) > api.MaxExtension {
		return "", fmt.Errorf("an extension can last at most %s", api.MaxExtension)
	}
	zone := zoneOf(*pe.policy)
	local, until := now.In(zone), p.Until.In(zone)
	// Midnight itself still belongs to the day that ends with it.
	if last := until.Add(-time.Nanosecond); local.YearDay() != last.YearDay() || local.Year() != last.Year() {
		return "", errors.New("an extension ends at midnight at the latest")
	}
	extensions := map[string]time.Time{}
	for user, end := range pe.state.Extensions {
		if now.Before(end) {
			extensions[user] = end
		}
	}
	// A shorter extension must not take time away that someone already has.
	if earlier := extensions[ruleUser]; earlier.After(p.Until) {
		until = earlier.In(zone)
		p.Until = earlier
	}
	extensions[ruleUser] = p.Until
	before := pe.state.Extensions
	pe.state.Extensions = extensions
	if err := pe.saveState(); err != nil {
		pe.state.Extensions = before
		return "", err
	}
	clock := until.Format("15:04")
	language := pe.policy.Language
	pe.popup(ctx, p.User, fmt.Sprintf(screenText(language, "given"), clock), urgencyNormal)
	return p.User + " may stay until " + clock, nil
}

func (a *Agent) extendScreenTime(task api.Task) api.TaskResult {
	if err := api.Validate(task.Type, task.Payload); err != nil {
		return api.TaskResult{OK: false, Output: err.Error()}
	}
	var p api.ScreenExtendPayload
	if err := json.Unmarshal(task.Payload, &p); err != nil {
		return api.TaskResult{OK: false, Output: err.Error()}
	}
	out, err := a.policy.Extend(context.Background(), p, time.Now())
	if err != nil {
		return api.TaskResult{OK: false, Output: err.Error()}
	}
	return api.TaskResult{OK: true, Output: out}
}
