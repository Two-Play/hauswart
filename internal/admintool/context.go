package admintool

import (
	"fmt"
	"strings"
	"time"
)

// When is how a time is shown next to a task: short, as it is recent.
const When = "02.01. 15:04"

// Since says how long ago something was, as a number and a unit: "now", "min",
// "h" or "d".
func Since(t, now time.Time) (int, string) {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return 0, "now"
	case d < time.Hour:
		return int(d / time.Minute), "min"
	case d < 48*time.Hour:
		return int(d / time.Hour), "h"
	}
	return int(d / (24 * time.Hour)), "d"
}

func ago(t, now time.Time) string {
	n, unit := Since(t, now)
	if unit == "now" {
		return "just now"
	}
	return fmt.Sprintf("%d %s ago", n, unit)
}

// contextLines says, in English, when and why a task was made and what is known
// about its device.
func contextLines(item Item, now time.Time) []string {
	var lines []string
	created := ""
	if !item.CreatedAt.IsZero() {
		created = " " + item.CreatedAt.Local().Format(When)
	}
	if item.Automatic() {
		lines = append(lines, "Created"+created+", approved automatically by a rule")
	} else {
		lines = append(lines, "Created"+created+" by "+item.CreatedBy)
	}
	if r := item.Request; r != nil {
		line := "Requested by " + r.User
		if !r.At.IsZero() {
			line += " on " + r.At.Local().Format(When)
		}
		if r.Reason != "" {
			line += ": “" + r.Reason + "”"
		}
		lines = append(lines, line)
	}
	device := []string{"Device: " + item.Hostname}
	if item.Hostname == "" {
		device[0] = "Device: unknown host"
	}
	if item.LastSeen.IsZero() {
		device = append(device, "never seen")
	} else {
		device = append(device, "last seen "+ago(item.LastSeen, now))
	}
	// An older agent does not say, so no names is no proof that nobody is there.
	if len(item.Sessions) > 0 {
		device = append(device, "logged in: "+SessionList(item.Sessions, "active"))
	}
	return append(lines, strings.Join(device, " · "))
}

// SessionList names who is logged in, with the given word after the one in front.
func SessionList(sessions []LoggedIn, active string) string {
	names := make([]string, len(sessions))
	for i, s := range sessions {
		names[i] = s.User
		if s.Active {
			names[i] += " (" + active + ")"
		}
	}
	return strings.Join(names, ", ")
}

func printContext(item Item) {
	for _, line := range contextLines(item, time.Now()) {
		fmt.Println("  " + line)
	}
}
