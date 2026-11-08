package admintool

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/Two-Play/hauswart/internal/api"
)

// clean makes text from the server safe to print. Without it, escape sequences
// could hide or fake what the admin is about to sign.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		// Format characters such as bidi overrides could make text read
		// differently from what is signed, as api.ValidText knows.
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
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

// reviewers maps the task types this tool will sign to how it presents them.
// Password hashes and keys are missing on purpose: those come from this tool,
// never from the queue. Each feature registers its types from its own file.
var reviewers = map[string]func(json.RawMessage) (string, []byte, error){}

// reviewer registers a type. The payload is decoded into the typed value that
// is both shown and encoded again, so what is signed is what was shown, and
// bytes from the server are never signed as they came.
func reviewer[T any](taskType string, show func(T) (string, error)) {
	reviewers[taskType] = func(raw json.RawMessage) (string, []byte, error) {
		var p T
		if err := json.Unmarshal(raw, &p); err != nil {
			return "", nil, err
		}
		text, err := show(p)
		if err != nil {
			return "", nil, err
		}
		payload, err := json.Marshal(p)
		return text, bytes.TrimSpace(payload), err
	}
}

// review turns a task from the server into what the admin sees and signs.
func review(taskType string, raw json.RawMessage) (string, []byte, error) {
	if err := api.Validate(taskType, raw); err != nil {
		return "", nil, err
	}
	show, ok := reviewers[taskType]
	if !ok {
		return "", nil, fmt.Errorf("refusing to sign task type %s from the server", clean(taskType))
	}
	return show(raw)
}

func init() {
	packages := func(verb string) func(api.PackagesPayload) (string, error) {
		return func(p api.PackagesPayload) (string, error) {
			return fmt.Sprintf("%s: %s", verb, strings.Join(p.Packages, ", ")), nil
		}
	}
	reviewer(api.TaskPkgInstall, packages("Install packages as root"))
	reviewer(api.TaskPkgRemove, packages("Remove packages"))
	reviewer(api.TaskFlatpakInstall, packages("Install Flatpaks system-wide"))
	reviewer(api.TaskFilePut, func(p api.FilePutPayload) (string, error) {
		mode := p.Mode
		if mode == "" {
			mode = "0644"
		}
		sum := sha256.Sum256([]byte(p.Content))
		return fmt.Sprintf("Write file %s, mode %s, SHA-256 %x:\n%s", p.Path, mode, sum, cleanLines(p.Content)), nil
	})
	reviewer(api.TaskCAInstall, func(p api.CAInstallPayload) (string, error) {
		block, _ := pem.Decode([]byte(p.PEM))
		sum := sha256.Sum256(block.Bytes)
		return fmt.Sprintf("TRUST A CERTIFICATE AUTHORITY on this device, which can then intercept TLS.\n"+
			"  Name: %s\n  SHA-256: %x\n  Compare this with the certificate you meant to deploy.", p.Name, sum), nil
	})
	reviewer(api.TaskSudoGrant, func(p api.SudoGrantPayload) (string, error) {
		if !time.Now().Before(p.ExpiresAt) {
			return "", fmt.Errorf("grant expired at %s", p.ExpiresAt.Format(time.RFC3339))
		}
		rights := "FULL ROOT, all commands"
		if len(p.Commands) > 0 {
			rights = "commands " + strings.Join(p.Commands, ", ")
		}
		return fmt.Sprintf("Grant sudo to %s: %s\n  Ends %s (in %s)", p.User, rights,
			p.ExpiresAt.Local().Format(time.RFC1123), time.Until(p.ExpiresAt).Round(time.Minute)), nil
	})
	reviewer(api.TaskUserCreate, func(p api.UserPayload) (string, error) {
		return fmt.Sprintf("Create Linux user %s, name %q, groups %q", p.User, clean(p.FullName), p.Groups), nil
	})
	reviewer(api.TaskUserLock, func(p api.UserPayload) (string, error) {
		return "Lock Linux user " + p.User, nil
	})
	reviewer(api.TaskUserUnlock, func(p api.UserPayload) (string, error) {
		return "Unlock Linux user " + p.User, nil
	})
	reviewer(api.TaskLimitSet, func(p api.LimitPayload) (string, error) {
		return fmt.Sprintf("Limit Linux user %s: CPU %d%%, memory %d MB (0 means no limit)", p.User, p.CPUPercent, p.MemoryMB), nil
	})
}
