package agent

import (
	"slices"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

const (
	// screenLogout is how long the full-screen block covers a session before
	// the agent ends it. Programs keep running until then.
	screenLogout = 10 * time.Minute
	// nextAllowedStep is how finely the search for the next allowed minute walks.
	nextAllowedStep = time.Minute
)

// screenBlock is someone whose screen time ended, behind the full-screen block.
type screenBlock struct {
	user     string
	reason   string
	next     time.Time
	logoutAt time.Time
	// requestedAt is when more time was asked for from the block.
	requestedAt time.Time
}

// blockReason says why a rule does not let someone stay now: the daily quota
// is used up while a window would allow it, or no window allows it.
func blockReason(rule api.ScreenTimeRule, now time.Time) string {
	if rule.DailyMinutes == 0 {
		return api.ScreenReasonWindow
	}
	windowed := rule
	if len(windowed.Windows) == 0 {
		windowed.Windows = []api.Window{api.AllDay}
	}
	if _, inside := sessionEnd(windowed, now, time.Time{}); inside {
		return api.ScreenReasonQuota
	}
	return api.ScreenReasonWindow
}

// nextAllowed is the first moment within a week at which a rule lets someone
// use the device again: the quota counts again on a new day. Zero if there is
// none, such as a rule without windows on any day.
func nextAllowed(rule api.ScreenTimeRule, now time.Time, used time.Duration) time.Time {
	start := now.Truncate(nextAllowedStep).Add(nextAllowedStep)
	for at := start; at.Before(now.Add(maxSessionWalk)); at = at.Add(nextAllowedStep) {
		usedThen := time.Duration(0)
		if at.YearDay() == now.YearDay() && at.Year() == now.Year() {
			usedThen = used
		}
		if _, ok := ruleEnd(rule, at, time.Time{}, usedThen); ok {
			return at
		}
	}
	return time.Time{}
}

// ScreenBlocks lists who is behind the block for their screen time now.
func (pe *PolicyEngine) ScreenBlocks() []api.BlockState {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	language := ""
	if pe.policy != nil {
		language = pe.policy.Language
	}
	blocks := make([]api.BlockState, 0, len(pe.blocked))
	for _, b := range pe.blocked {
		blocks = append(blocks, api.BlockState{Kind: api.BlockScreen, User: b.user, Reason: b.reason,
			Next: b.next, LogoutAt: b.logoutAt, RequestedAt: b.requestedAt, Language: language})
	}
	slices.SortFunc(blocks, func(a, b api.BlockState) int { return a.LogoutAt.Compare(b.LogoutAt) })
	return blocks
}

// screenBlocked says whether someone is behind the block for their screen time.
func (pe *PolicyEngine) screenBlocked(user string) bool {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	for _, b := range pe.blocked {
		if b.user == user {
			return true
		}
	}
	return false
}

// screenRequested notes that someone asked for more time from the block, and
// says false if they did so too recently.
func (pe *PolicyEngine) screenRequested(user string, now time.Time, every time.Duration) bool {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	for _, b := range pe.blocked {
		if b.user != user {
			continue
		}
		if !b.requestedAt.IsZero() && now.Before(b.requestedAt.Add(every)) {
			return false
		}
		b.requestedAt = now
		return true
	}
	return false
}
