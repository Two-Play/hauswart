package admintool

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

func init() {
	reviewer(api.TaskPolicySet, func(p api.Policy) (string, error) {
		// The rules come last: file contents are long, and nothing that matters
		// may scroll away from the question.
		text := ""
		for _, file := range p.Files {
			text += fmt.Sprintf("Content of %s:\n%s\n  ", file.Path, cleanLines(file.Content))
		}
		text += "SET THE POLICY of this device. It enforces this on its own, without the server:\n"
		for _, line := range policyLines(p) {
			text += "    " + line + "\n"
		}
		return strings.TrimRight(text, "\n"), nil
	})
	reviewer(api.TaskScreenExtend, func(p api.ScreenExtendPayload) (string, error) {
		if err := stillValid(p.Until); err != nil {
			return "", err
		}
		return fmt.Sprintf("Let %s stay logged in until %s (in %s), beyond the screen time rules.",
			p.User, p.Until.Local().Format(time.RFC1123), time.Until(p.Until).Round(time.Minute)), nil
	})
	reviewer(api.TaskPolicyClear, func(struct{}) (string, error) {
		return "REMOVE THE POLICY of this device. Its rules end, including parental controls,\n" +
			"  and CAs from the policy are no longer trusted. Packages and files stay.", nil
	})
}

// policyLines describes a policy with one line per rule, so that a comparison of
// two policies is a comparison of lines. Anything that changes what a device
// does has to change a line.
func policyLines(p api.Policy) []string {
	var lines []string
	add := func(format string, args ...any) { lines = append(lines, clean(fmt.Sprintf(format, args...))) }
	for _, name := range p.RequiredPackages {
		add("required package %s", name)
	}
	for _, name := range p.ForbiddenPackages {
		add("forbidden package %s", name)
	}
	for _, name := range p.RequiredFlatpaks {
		add("required Flatpak %s", name)
	}
	for _, name := range p.ForbiddenFlatpaks {
		add("forbidden Flatpak %s", name)
	}
	for _, file := range p.Files {
		mode := file.Mode
		if mode == "" {
			mode = "0644"
		}
		add("file %s, mode %s, SHA-256 %x", file.Path, mode, sha256.Sum256([]byte(file.Content)))
	}
	for _, ca := range p.CAs {
		block, _ := pem.Decode([]byte(ca.PEM))
		add("TRUSTED CA %s, which can intercept TLS, SHA-256 %x", ca.Name, sha256.Sum256(block.Bytes))
	}
	if p.Updates != nil {
		add("automatic updates %s, reboot: %s", windowText(p.Updates.Window), p.Updates.Reboot)
	}
	if p.Security != nil {
		if p.Security.Firewall {
			add("firewall enforced")
		}
		if p.Security.DiskEncryption {
			add("disk encryption checked")
		}
		if p.Security.ScreenLock {
			add("screen lock checked")
		}
	}
	if p.TimeZone != "" {
		add("time zone %s", p.TimeZone)
	}
	for _, rule := range p.ScreenTime {
		var windows []string
		for _, window := range rule.Windows {
			windows = append(windows, windowText(window))
		}
		times := "NEVER"
		if len(windows) > 0 {
			times = strings.Join(windows, "; ")
		}
		add("user %s may be logged in: %s", rule.User, times)
	}
	if p.Language != "" {
		add("warnings in %s", p.Language)
	}
	if d := p.Directory; d != nil {
		block, _ := pem.Decode([]byte(d.CA))
		add("ACCOUNTS FROM %s MAY LOG IN, base %s, read as %s, password SHA-256 %x", d.URI, d.BaseDN, d.BindDN,
			sha256.Sum256([]byte(d.BindPassword)))
		add("directory identified by the CA with SHA-256 %x", sha256.Sum256(block.Bytes))
	}
	for _, rule := range p.Apps {
		if rule.BlockDownloads || rule.Strict || len(rule.ForbiddenPrograms) > 0 {
			add("user %s may not start programs from home, temporary folders, shares or sticks", rule.User)
		}
		for _, program := range rule.ForbiddenPrograms {
			add("user %s may not start %s", rule.User, program)
		}
		if rule.Strict {
			add("user %s may ONLY start these applications from the menu: %s", rule.User, strings.Join(rule.AllowedApps, ", "))
			if rule.Flatpaks == nil {
				add("user %s may use no Flatpak", rule.User)
			}
		} else if len(rule.AllowedApps) > 0 {
			add("user %s has a list of applications that only counts when strict: %s", rule.User, strings.Join(rule.AllowedApps, ", "))
		}
		if rule.Flatpaks != nil {
			add("user %s Flatpaks, %s: %s, and none of their own", rule.User, rule.Flatpaks.Mode, strings.Join(rule.Flatpaks.Apps, ", "))
		}
	}
	for _, mount := range p.Mounts {
		add("share //%s/%s appears in /media as USER-%s, with the login password", mount.Server, mount.Share, mount.Folder)
	}
	if n := p.Nextcloud; n != nil {
		add("Nextcloud %s as %s", n.URL, n.Mode)
	}
	return lines
}

func windowText(w api.Window) string {
	return strings.Join(w.Days, ",") + " " + w.Start + "-" + w.End
}

// policyFingerprint identifies a policy task's effect, and is empty for all other
// tasks. It is made from what would be signed.
func policyFingerprint(taskType string, payload []byte) string {
	if taskType != api.TaskPolicySet && taskType != api.TaskPolicyClear {
		return ""
	}
	return fmt.Sprintf("%s %x", taskType, sha256.Sum256(payload))
}

// policyWarning points out what the text of a policy cannot show. The CA of the
// Hauswart server would let a hacked server pose as the directory, and whoever
// does that logs in as anyone.
func policyWarning(cfg *config, taskType string, payload []byte) string {
	if taskType != api.TaskPolicySet {
		return ""
	}
	var p api.Policy
	if json.Unmarshal(payload, &p) != nil || p.Directory == nil || cfg.CA == "" {
		return ""
	}
	if strings.TrimSpace(p.Directory.CA) == strings.TrimSpace(cfg.CA) {
		return "  WARNING: the directory uses the CA of the Hauswart server. A hacked server could then pose as\n" +
			"  the directory and log in to this device as anyone. Use a CA the server does not hold."
	}
	return ""
}

// identicalPolicies says what the same policy would change on the other devices
// that wait for it. The same document can mean something else on each of them,
// such as the end of someone's screen time, and the server chooses which device
// comes first. So all of this is on the screen before anyone agrees to it. Only
// devices named on this computer count: the admin has to know what they agree to.
func identicalPolicies(cfg *config, rest []queued, fingerprint string) []string {
	var lines []string
	for _, task := range rest {
		known := cfg.Devices[task.DeviceID]
		if known == nil || known.Name == "" {
			continue
		}
		if _, payload, err := review(task.Type, task.Payload); err == nil && policyFingerprint(task.Type, payload) == fingerprint {
			lines = append(lines, fmt.Sprintf("  On %s:\n%s", clean(known.Name), policyChanges(task.DeviceID, task.Type, payload)))
		}
	}
	return lines
}

// policyPath is where the last signed policy of a device is kept. It stays on
// this computer: a comparison with anything from the server would prove nothing.
func policyPath(device string) (string, error) {
	path, err := configPath()
	if err != nil {
		return "", err
	}
	if device == "" || device != filepath.Base(device) || strings.HasPrefix(device, ".") {
		return "", fmt.Errorf("invalid device ID %q", clean(device))
	}
	return filepath.Join(filepath.Dir(path), "policies", device+".json"), nil
}

func lastPolicy(device string) (*api.Policy, error) {
	path, err := policyPath(device)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p api.Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// rememberPolicy runs after a signature, so that the next review compares with
// what was really signed.
func rememberPolicy(device, taskType string, payload []byte) error {
	path, err := policyPath(device)
	if err != nil {
		return err
	}
	if taskType == api.TaskPolicyClear {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o600)
}

// policyChanges says what a signature would change against the last one.
func policyChanges(device, taskType string, payload []byte) string {
	before, err := lastPolicy(device)
	if err != nil {
		return "  Cannot compare with the last signed policy: " + clean(err.Error())
	}
	if before == nil {
		if taskType == api.TaskPolicyClear {
			return "  You have not signed a policy for this device from here, so it is unknown what ends."
		}
		return "  You have not signed a policy for this device from here, so all of it is new."
	}
	var after api.Policy
	if taskType == api.TaskPolicySet {
		if err := json.Unmarshal(payload, &after); err != nil {
			return "  Cannot compare with the last signed policy: " + clean(err.Error())
		}
	}
	return diffPolicies(*before, after)
}

func diffPolicies(before, after api.Policy) string {
	old, next := policyLines(before), policyLines(after)
	var changes []string
	for _, line := range old {
		if !slices.Contains(next, line) {
			changes = append(changes, "    - "+line)
		}
	}
	for _, line := range next {
		if !slices.Contains(old, line) {
			changes = append(changes, "    + "+line)
		}
	}
	if len(changes) == 0 {
		return "  Nothing changed since you last signed for this device."
	}
	return "  Changes since you last signed for this device:\n" + strings.Join(changes, "\n")
}
