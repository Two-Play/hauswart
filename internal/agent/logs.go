package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/philippe/hauswart/internal/api"
)

const (
	agentUnit = "hauswart-agent.service"
	// Entries are filtered after reading, so more are read than are wanted.
	logOverfetch  = 4
	maxLogMessage = 1024
	maxLogBytes   = 256 << 10
	nobodyUID     = 65534
	unsetLoginUID = 4294967295
)

func init() {
	handleData(api.TaskLogsFetch, (*Executor).logsFetch)
}

func (e *Executor) logsFetch(ctx context.Context, p api.LogsPayload) (string, json.RawMessage, error) {
	lines := p.Lines
	if lines == 0 {
		lines = api.DefaultLogLines
	}
	result := api.LogsResult{Available: true, Agent: []api.LogEntry{}, System: []api.LogEntry{}}
	for _, part := range []struct {
		target *[]api.LogEntry
		filter string
	}{
		{&result.Agent, "--unit=" + agentUnit},
		{&result.System, "--priority=warning"},
	} {
		entries, withheld, ok, err := e.readJournal(ctx, lines, part.filter)
		if err != nil {
			return "", nil, err
		}
		if !ok {
			raw, err := json.Marshal(api.LogsResult{Agent: []api.LogEntry{}, System: []api.LogEntry{}})
			return "this device has no journal", raw, err
		}
		*part.target = entries
		result.Withheld += withheld
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return "", nil, err
	}
	return fmt.Sprintf("%d agent and %d system entries, %d withheld",
		len(result.Agent), len(result.System), result.Withheld), raw, nil
}

// readJournal reports ok as false if the device has no journal to read.
//
// --system alone would not keep user messages out. It only skips the files of
// users, and a journal in /run or with SplitMode=none holds everything in the
// system file, so every entry also passes through belongsToUser.
func (e *Executor) readJournal(ctx context.Context, lines int, filter string) ([]api.LogEntry, int, bool, error) {
	out, err := e.Run(ctx, "journalctl", "--system", "--no-pager", "--output=json",
		fmt.Sprintf("--lines=%d", lines*logOverfetch), filter)
	// Depending on the version, a system without journal files says so, or
	// reports nothing at all and no error either.
	if errors.Is(err, exec.ErrNotFound) || strings.Contains(out, "No journal files were found") ||
		(err == nil && strings.TrimSpace(out) == "" && !e.hasJournalFiles()) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, fmt.Errorf("journalctl: %w: %s", err, clip(out, 300))
	}
	entries, withheld := parseJournal(out)
	return newestEntries(entries, lines), withheld, true, nil
}

func (e *Executor) hasJournalFiles() bool {
	for _, dir := range []string{"/var/log/journal", "/run/log/journal"} {
		// Without a machine ID, the files are not in a subdirectory.
		for _, pattern := range []string{"/*.journal", "/*/*.journal"} {
			if files, _ := filepath.Glob(e.path(dir) + pattern); len(files) > 0 {
				return true
			}
		}
	}
	return false
}

// parseJournal reads journalctl's JSON lines. The output also holds stderr, and
// anything that is not an entry is left out rather than shown.
func parseJournal(out string) ([]api.LogEntry, int) {
	entries := []api.LogEntry{}
	withheld := 0
	for line := range strings.Lines(out) {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			continue
		}
		if belongsToUser(fields) {
			withheld++
			continue
		}
		message := journalText(fields["MESSAGE"])
		if message == "" {
			continue
		}
		entries = append(entries, api.LogEntry{
			Time:     journalTime(fields),
			Priority: journalPriority(fields),
			Source:   journalSource(fields),
			Message:  message,
		})
	}
	return entries, withheld
}

// Fields that exist only on messages from a user's own services.
var userFields = []string{
	"_SYSTEMD_USER_UNIT", "_SYSTEMD_USER_SLICE", "OBJECT_SYSTEMD_USER_UNIT", "COREDUMP_USER_UNIT",
}

// Fields that name the user a message comes from or is about. Those without a
// leading underscore can be set by the sender, which can only hide more.
var userIDFields = []string{
	"_UID", "_SYSTEMD_OWNER_UID", "_AUDIT_LOGINUID", "OBJECT_UID", "OBJECT_SYSTEMD_OWNER_UID",
	"OBJECT_AUDIT_LOGINUID", "COREDUMP_UID", "COREDUMP_OWNER_UID",
}

// belongsToUser decides what stays private. It errs towards withholding: an
// entry that cannot be read clearly counts as a user's.
func belongsToUser(fields map[string]json.RawMessage) bool {
	for _, name := range userFields {
		if _, ok := fields[name]; ok {
			return true
		}
	}
	for _, name := range userIDFields {
		raw, ok := fields[name]
		if !ok {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return true
		}
		id, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return true
		}
		if id >= minUserUID && id != nobodyUID && id != unsetLoginUID {
			return true
		}
	}
	switch journalText(fields["_TRANSPORT"]) {
	case "kernel", "driver":
		return false
	}
	// Everything inside a login session counts, even as root through sudo. A
	// message without a slice comes from a process that ended before journald
	// could look at it, so nobody can say where it ran.
	slice := journalText(fields["_SYSTEMD_SLICE"])
	return slice == "" || strings.HasPrefix(slice, "user-")
}

// journalText reads a field. The journal stores values that are not valid text
// as an array of bytes, and fields that occur twice as an array of values,
// which never counts as text.
func journalText(raw json.RawMessage) string {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		var data []uint8
		if err := json.Unmarshal(raw, &data); err != nil {
			return ""
		}
		text = strings.ToValidUTF8(string(data), "\uFFFD")
	}
	return clip(cleanText(text), maxLogMessage)
}

func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\t' {
			return ' '
		}
		return r
	}, s)
}

func journalTime(fields map[string]json.RawMessage) time.Time {
	micros, err := strconv.ParseInt(journalText(fields["__REALTIME_TIMESTAMP"]), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.UnixMicro(micros).UTC()
}

func journalPriority(fields map[string]json.RawMessage) int {
	priority, err := strconv.Atoi(journalText(fields["PRIORITY"]))
	if err != nil {
		return 6
	}
	return priority
}

func journalSource(fields map[string]json.RawMessage) string {
	for _, name := range []string{"_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER", "_COMM", "_TRANSPORT"} {
		if source := journalText(fields[name]); source != "" {
			return source
		}
	}
	return "unknown"
}

// newestEntries keeps the end of the list within the limits on entries and
// size, so that a result always fits the server's request limit.
func newestEntries(entries []api.LogEntry, lines int) []api.LogEntry {
	first := max(len(entries)-lines, 0)
	size := 0
	for i := len(entries) - 1; i >= first; i-- {
		size += len(entries[i].Message) + len(entries[i].Source)
		if size > maxLogBytes {
			first = i + 1
			break
		}
	}
	return entries[first:]
}

// clip cuts text to a number of bytes without splitting a character.
func clip(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return strings.ToValidUTF8(s[:limit], "") + "…"
}
