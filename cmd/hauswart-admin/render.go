package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/philippe/hauswart/internal/api"
)

// clean makes text from the server safe to print. Without it, escape sequences
// could hide or fake what the admin is about to sign.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '\ufffd'
		}
		return r
	}, s)
}

// cleanLines is clean for multi-line content.
func cleanLines(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = "    | " + clean(line)
	}
	return strings.Join(lines, "\n")
}

// review turns a task from the server into what the admin sees and what gets
// signed. Both come from the same typed value: the payload is decoded, shown
// and encoded again, so bytes from the server are never signed as they came.
func review(taskType string, raw json.RawMessage) (text string, payload []byte, err error) {
	if err := api.Validate(taskType, raw); err != nil {
		return "", nil, err
	}
	switch taskType {
	case api.TaskPkgInstall, api.TaskPkgRemove, api.TaskFlatpakInstall:
		var p api.PackagesPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			return "", nil, err
		}
		verb := map[string]string{
			api.TaskPkgInstall:     "Install packages as root",
			api.TaskPkgRemove:      "Remove packages",
			api.TaskFlatpakInstall: "Install Flatpaks system-wide",
		}[taskType]
		text = fmt.Sprintf("%s: %s", verb, strings.Join(p.Packages, ", "))
		payload, err = json.Marshal(p)
	case api.TaskFilePut:
		var p api.FilePutPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			return "", nil, err
		}
		mode := p.Mode
		if mode == "" {
			mode = "0644"
		}
		sum := sha256.Sum256([]byte(p.Content))
		text = fmt.Sprintf("Write file %s, mode %s, SHA-256 %x:\n%s", p.Path, mode, sum, cleanLines(p.Content))
		payload, err = json.Marshal(p)
	case api.TaskCAInstall:
		var p api.CAInstallPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			return "", nil, err
		}
		block, _ := pem.Decode([]byte(p.PEM))
		sum := sha256.Sum256(block.Bytes)
		text = fmt.Sprintf("TRUST A CERTIFICATE AUTHORITY on this device, which can then intercept TLS.\n"+
			"  Name: %s\n  SHA-256: %x\n  Compare this with the certificate you meant to deploy.", p.Name, sum)
		payload, err = json.Marshal(p)
	case api.TaskSudoGrant:
		var p api.SudoGrantPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			return "", nil, err
		}
		if !time.Now().Before(p.ExpiresAt) {
			return "", nil, fmt.Errorf("grant expired at %s", p.ExpiresAt.Format(time.RFC3339))
		}
		rights := "FULL ROOT, all commands"
		if len(p.Commands) > 0 {
			rights = "commands " + strings.Join(p.Commands, ", ")
		}
		text = fmt.Sprintf("Grant sudo to %s: %s\n  Ends %s (in %s)", p.User, rights,
			p.ExpiresAt.Local().Format(time.RFC1123), time.Until(p.ExpiresAt).Round(time.Minute))
		payload, err = json.Marshal(p)
	case api.TaskUserCreate:
		var p api.UserPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			return "", nil, err
		}
		text = fmt.Sprintf("Create Linux user %s, name %q, groups %q", p.User, clean(p.FullName), p.Groups)
		payload, err = json.Marshal(p)
	case api.TaskUserLock, api.TaskUserUnlock:
		var p api.UserPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			return "", nil, err
		}
		verb := "Lock"
		if taskType == api.TaskUserUnlock {
			verb = "Unlock"
		}
		text = fmt.Sprintf("%s Linux user %s", verb, p.User)
		payload, err = json.Marshal(p)
	case api.TaskLimitSet:
		var p api.LimitPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			return "", nil, err
		}
		text = fmt.Sprintf("Limit Linux user %s: CPU %d%%, memory %d MB (0 means no limit)", p.User, p.CPUPercent, p.MemoryMB)
		payload, err = json.Marshal(p)
	default:
		// Password hashes and keys come from this tool, never from the queue.
		return "", nil, fmt.Errorf("refusing to sign task type %s from the server", clean(taskType))
	}
	if err != nil {
		return "", nil, err
	}
	return text, bytes.TrimSpace(payload), nil
}
