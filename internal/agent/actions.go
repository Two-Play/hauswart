package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"os/user"

	"github.com/Two-Play/hauswart/internal/api"
)

const (
	// popupTitle is fixed, so that a message cannot pose as the system. The
	// app name shown next to it is the same.
	popupTitle = "Hauswart"
	// popupTimeout limits what a user's own session bus can delay the agent.
	popupTimeout = 15 * time.Second
	// scheduledFile is where logind keeps a pending shutdown.
	scheduledFile = "/run/systemd/shutdown/scheduled"

	urgencyNormal   = "1"
	urgencyCritical = "2"
)

var sessionIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func init() {
	handle(api.TaskPowerReboot, func(e *Executor, ctx context.Context, p api.PowerPayload) (string, error) {
		return e.power(ctx, "-r", "restart", p)
	})
	handle(api.TaskPowerShutdown, func(e *Executor, ctx context.Context, p api.PowerPayload) (string, error) {
		return e.power(ctx, "-P", "shut down", p)
	})
	handle(api.TaskPowerCancel, func(e *Executor, ctx context.Context, _ struct{}) (string, error) {
		return e.powerCancel(ctx)
	})
	handle(api.TaskNotifySend, (*Executor).notifySend)
	handle(api.TaskGroupAdd, func(e *Executor, ctx context.Context, p api.GroupPayload) (string, error) {
		return e.groupChange(ctx, p, true)
	})
	handle(api.TaskGroupRemove, func(e *Executor, ctx context.Context, p api.GroupPayload) (string, error) {
		return e.groupChange(ctx, p, false)
	})
}

// power schedules through shutdown, which warns terminals and blocks new logins
// shortly before. Desktops see nothing of that, so they get a popup as well.
// The text starts with a fixed word, so it can never be read as an option.
func (e *Executor) power(ctx context.Context, flag, verb string, p api.PowerPayload) (string, error) {
	if !time.Now().Before(p.ExpiresAt) {
		return "", fmt.Errorf("task expired at %s", p.ExpiresAt.Format(time.RFC3339))
	}
	warning := fmt.Sprintf("Hauswart: this device will %s in %d minute(s).", verb, p.DelayMinutes)
	if p.Message != "" {
		warning += " " + p.Message
	}
	if out, err := e.Run(ctx, "shutdown", flag, "+"+strconv.Itoa(p.DelayMinutes), warning); err != nil {
		return out, err
	}
	// Without a warning, the device still has to go down as ordered.
	warned, failed := e.popup(ctx, "", strings.TrimPrefix(warning, "Hauswart: "), urgencyCritical)
	return fmt.Sprintf("%s scheduled in %d minute(s), %s", verb, p.DelayMinutes, popupReport(warned, failed)), nil
}

func (e *Executor) powerCancel(ctx context.Context) (string, error) {
	if _, err := os.Stat(e.path(scheduledFile)); errors.Is(err, os.ErrNotExist) {
		return "nothing was scheduled", nil
	}
	if out, err := e.Run(ctx, "shutdown", "-c"); err != nil {
		return out, err
	}
	warned, failed := e.popup(ctx, "", "The scheduled restart or shutdown was cancelled.", urgencyNormal)
	return "cancelled, " + popupReport(warned, failed), nil
}

func (e *Executor) notifySend(ctx context.Context, p api.NotifyPayload) (string, error) {
	if !time.Now().Before(p.ExpiresAt) {
		return "", fmt.Errorf("task expired at %s", p.ExpiresAt.Format(time.RFC3339))
	}
	shown, failed := e.popup(ctx, p.User, p.Message, urgencyNormal)
	report := popupReport(shown, failed)
	// Nobody saw it, and the admin should not believe otherwise.
	if len(shown) == 0 || len(failed) > 0 {
		return "", errors.New(report)
	}
	return report, nil
}

func popupReport(shown, failed []string) string {
	report := "popup shown to nobody"
	if len(shown) > 0 {
		report = "popup shown to " + strings.Join(shown, ", ")
	}
	if len(failed) > 0 {
		report += ", failed for " + strings.Join(failed, ", ")
	}
	return report
}

// popup shows a message in the desktop sessions of one user, or of everyone if
// only is empty. It returns who got it and for whom it failed.
func (e *Executor) popup(ctx context.Context, only, message, urgency string) (shown, failed []string) {
	people, err := e.desktopUsers(ctx)
	if err != nil {
		return nil, []string{err.Error()}
	}
	for _, person := range people {
		if only != "" && person.Username != only {
			continue
		}
		if err := e.notifyUser(ctx, person, message, urgency); err != nil {
			failed = append(failed, person.Username)
		} else {
			shown = append(shown, person.Username)
		}
	}
	return shown, failed
}

// desktopUsers finds the people with a graphical session. The login screen has
// its own class and is left out, like system accounts and remote sessions.
func (e *Executor) desktopUsers(ctx context.Context) ([]*user.User, error) {
	sessions, err := e.graphicalSessions(ctx)
	if err != nil {
		return nil, err
	}
	var people []*user.User
	for _, session := range sessions {
		if !slices.ContainsFunc(people, func(u *user.User) bool { return u.Uid == session.person.Uid }) {
			people = append(people, session.person)
		}
	}
	return people, nil
}

// graphicalSession is a graphical session of an ordinary account.
type graphicalSession struct {
	person *user.User
	// desktop is what the session calls itself, such as gnome or KDE.
	desktop string
}

func (e *Executor) graphicalSessions(ctx context.Context) ([]graphicalSession, error) {
	out, err := e.Run(ctx, "loginctl", "list-sessions", "--no-legend")
	if err != nil {
		return nil, errors.New("loginctl failed, is this a systemd device?")
	}
	var sessions []graphicalSession
	for line := range strings.Lines(out) {
		fields := strings.Fields(line)
		if len(fields) == 0 || !sessionIDRe.MatchString(fields[0]) {
			continue
		}
		shown, err := e.Run(ctx, "loginctl", "show-session", fields[0],
			"-p", "Name", "-p", "Type", "-p", "Class", "-p", "State", "-p", "Remote", "-p", "Desktop")
		if err != nil {
			continue // the session ended in the meantime
		}
		session := parseProperties(shown)
		if !graphical(session) || !api.ValidUser(session["Name"]) {
			continue
		}
		person, err := e.lookupUser(session["Name"])
		if err != nil {
			continue
		}
		if uid, _ := strconv.Atoi(person.Uid); uid < minUserUID {
			continue
		}
		sessions = append(sessions, graphicalSession{person: person, desktop: session["Desktop"]})
	}
	return sessions, nil
}

func graphical(session map[string]string) bool {
	return (session["Type"] == "wayland" || session["Type"] == "x11") &&
		strings.HasPrefix(session["Class"], "user") &&
		(session["State"] == "active" || session["State"] == "online") &&
		session["Remote"] != "yes"
}

func parseProperties(text string) map[string]string {
	properties := map[string]string{}
	for line := range strings.Lines(text) {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			properties[key] = value
		}
	}
	return properties
}

// notifyUser speaks to the notification service on the user's own session bus.
// It runs with the user's rights, because that bus belongs to them and whatever
// answers on it is under their control. busctl comes with systemd, so this
// needs no extra package. The body may hold markup, which is escaped: a message
// must not bring its own links or images.
func (e *Executor) notifyUser(ctx context.Context, person *user.User, message, urgency string) error {
	ctx, cancel := context.WithTimeout(ctx, popupTimeout)
	defer cancel()
	_, err := e.Run(ctx, "runuser", "-u", person.Username, "--",
		"env", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/"+person.Uid+"/bus",
		"busctl", "--user", "--", "call",
		"org.freedesktop.Notifications", "/org/freedesktop/Notifications", "org.freedesktop.Notifications",
		"Notify", "susssasa{sv}i",
		popupTitle, "0", "dialog-information", popupTitle, escapeMarkup(message),
		"0", "1", "urgency", "y", urgency, "-1")
	return err
}

var markup = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func escapeMarkup(s string) string { return markup.Replace(s) }

// groupChange changes the membership of an ordinary account. The name check
// happened in api.Validate; what a name means is only known here, on the device.
func (e *Executor) groupChange(ctx context.Context, p api.GroupPayload, add bool) (string, error) {
	u, err := e.lookupUser(p.User)
	if err != nil {
		return "", err
	}
	if uid, _ := strconv.Atoi(u.Uid); uid < minUserUID {
		return "", fmt.Errorf("refusing to change system account %s", p.User)
	}
	group, err := user.LookupGroup(p.Group)
	if err != nil {
		return "", fmt.Errorf("group %s does not exist on this device", p.Group)
	}
	if group.Gid == "0" {
		return "", fmt.Errorf("refusing group %s, it has the rights of root", p.Group)
	}
	inSudoers, err := e.groupInSudoers(p.Group)
	if err != nil {
		return "", err
	}
	if inSudoers {
		return "", fmt.Errorf("refusing group %s, sudoers gives it rights", p.Group)
	}
	flag, report := "-d", "removed "+p.User+" from "+p.Group
	if add {
		flag, report = "-a", "added "+p.User+" to "+p.Group
	}
	if out, err := e.Run(ctx, "gpasswd", flag, p.User, p.Group); err != nil {
		return out, err
	}
	return report + ", effective at the next login", nil
}

// groupInSudoers catches groups that only this device treats as privileged. A
// name on a fixed list cannot know about a local "%family ALL=(ALL) ALL".
func (e *Executor) groupInSudoers(group string) (bool, error) {
	byName := regexp.MustCompile(`%:?` + regexp.QuoteMeta(group) + `([^a-z0-9_-]|$)`)
	var byID *regexp.Regexp
	if g, err := user.LookupGroup(group); err == nil {
		// sudo also takes a group by its number, written %#1001.
		byID = regexp.MustCompile(`%:?#` + regexp.QuoteMeta(g.Gid) + `([^0-9]|$)`)
	}
	files, err := filepath.Glob(e.path("/etc/sudoers.d/*"))
	if err != nil {
		return false, err
	}
	queue := append([]string{e.path("/etc/sudoers")}, files...)
	seen := map[string]bool{}
	for len(queue) > 0 {
		file := queue[0]
		queue = queue[1:]
		if seen[file] || len(seen) > 256 {
			continue
		}
		seen[file] = true
		raw, err := os.ReadFile(file)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		for line := range strings.Lines(string(raw)) {
			text := strings.TrimSpace(line)
			// Files named by @include and @includedir hold rules as well; the old
			// spelling starts with #, which is otherwise a comment.
			if directive, target, ok := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(text, "@"), "#"), " "); ok &&
				(directive == "include" || directive == "includedir") {
				target = strings.TrimSpace(target)
				if !filepath.IsAbs(target) {
					target = filepath.Join("/etc", target)
				}
				if directive == "include" {
					queue = append(queue, e.path(target))
				} else if more, err := filepath.Glob(e.path(filepath.Join(target, "*"))); err == nil {
					queue = append(queue, more...)
				}
				continue
			}
			if strings.HasPrefix(text, "#") {
				continue
			}
			if byID != nil && byID.MatchString(text) {
				return true, nil
			}
			// A # after the start may still begin a comment.
			if rule, _, _ := strings.Cut(text, " #"); byName.MatchString(rule) {
				return true, nil
			}
		}
	}
	return false, nil
}
