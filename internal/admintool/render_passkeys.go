package admintool

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Two-Play/hauswart/internal/api"
)

// passkeyTypeLabels say what each type a passkey can approve does, with what
// it puts at stake.
var passkeyTypeLabels = map[string]string{
	api.TaskPkgInstall:     "install packages (their scripts run as root)",
	api.TaskPkgRemove:      "remove packages",
	api.TaskPkgUpgrade:     "update all packages",
	api.TaskFlatpakInstall: "install Flatpaks from Flathub",
	"power.reboot":         "restart the device",
	"power.shutdown":       "shut the device down",
	"power.cancel":         "cancel a restart or shutdown",
	"notify.send":          "show a desktop message",
	api.TaskScreenExtend:   "give more screen time today",
	api.TaskAccessSet:      "block or open the device, for at most a day",
	api.TaskTerminalOpen:   "open a live ROOT SHELL for up to 4 hours",
}

func passkeyTypeLabel(t string) string {
	if label, ok := passkeyTypeLabels[t]; ok {
		return label + " (" + t + ")"
	}
	return t
}

func init() {
	reviewer(api.TaskPasskeyTypes, func(p api.PasskeyTypesPayload) (string, error) {
		p.Types = append([]string{}, api.SortedTypes(p.Types)...)
		var b strings.Builder
		b.WriteString("SET WHAT A PASSKEY MAY APPROVE on this device.")
		if len(p.Types) == 0 {
			b.WriteString("\n  A passkey approves nothing; everything needs a signature from this tool.")
		} else {
			b.WriteString("\n  A passkey may approve:")
			for _, t := range p.Types {
				b.WriteString("\n    + " + passkeyTypeLabel(t))
			}
		}
		var signatureOnly []string
		for _, t := range api.PasskeyCapable {
			if !slices.Contains(p.Types, t) {
				signatureOnly = append(signatureOnly, t)
			}
		}
		if len(signatureOnly) > 0 {
			b.WriteString("\n  Only with a signature:")
			for _, t := range signatureOnly {
				b.WriteString("\n    - " + passkeyTypeLabel(t))
			}
		}
		b.WriteString("\n  Everything else, such as sudo, keys, files and CAs, always needs a signature.")
		return b.String(), nil
	})
}

// passkeyTypeChanges says what a list would add and take away on a device,
// against what its last report says it has. The report comes through the
// server, so this is a hint; the list above is what gets signed.
func passkeyTypeChanges(report *api.Report, payload []byte) string {
	var p api.PasskeyTypesPayload
	if err := jsonUnmarshal(payload, &p); err != nil || report == nil {
		return "  The device has not said what a passkey may approve on it now."
	}
	var lines []string
	for _, t := range p.Types {
		if !slices.Contains(report.PasskeyTypes, t) {
			lines = append(lines, "  NEW BY PASSKEY: "+passkeyTypeLabel(t))
		}
	}
	for _, t := range report.PasskeyTypes {
		if !slices.Contains(p.Types, t) {
			lines = append(lines, "  no longer by passkey: "+passkeyTypeLabel(clean(t)))
		}
	}
	if len(lines) == 0 {
		return "  The device reports this list already."
	}
	return fmt.Sprintf("  Against what the device reports:\n%s", strings.Join(lines, "\n"))
}
