package api

import "time"

// TaskLogsFetch reads device logs. It takes no unit, path or filter, so the
// server has no say in what the agent reads beyond how many lines.
const TaskLogsFetch = "logs.fetch"

const (
	DefaultLogLines = 200
	MaxLogLines     = 500
)

// LogsPayload asks for the newest Lines entries of each log. Zero means
// DefaultLogLines.
type LogsPayload struct {
	Lines int `json:"lines,omitempty"`
}

// LogEntry is one journal message.
type LogEntry struct {
	Time     time.Time `json:"time"`
	Priority int       `json:"priority"`
	Source   string    `json:"source"`
	Message  string    `json:"message"`
}

// LogsResult is the structured result of TaskLogsFetch.
type LogsResult struct {
	// Available is false on a device without a journal.
	Available bool `json:"available"`
	// Agent is the Hauswart unit at every priority, System all system messages
	// from warning up. Both run from old to new.
	Agent  []LogEntry `json:"agent"`
	System []LogEntry `json:"system"`
	// Withheld counts entries that were left out because they belong to a user.
	Withheld int `json:"withheld"`
}

func init() {
	// Reading gains an attacker nothing on the device itself. What it means
	// for privacy is described in docs/security.md.
	register(TaskLogsFetch, true, checkLogs)
}

func checkLogs(p LogsPayload) error {
	if p.Lines < 0 || p.Lines > MaxLogLines {
		return Fail(ErrInvalidPayload, "lines")
	}
	return nil
}
