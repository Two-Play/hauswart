package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Two-Play/hauswart/internal/api"
)

const (
	deviationWifi    = "wifi"
	deviationPrinter = "printer"
	// nmConnections is where NetworkManager keeps system connections, readable by
	// root only, which matters for the passwords in them.
	nmConnections = "/etc/NetworkManager/system-connections"
	// Our own files and queues carry this prefix, so others stay untouched.
	networkPrefix = "hauswart-"
)

// wifiFile is the file of a network, named after a hash: an SSID may hold any
// byte, and a file name must not.
func wifiFile(ssid string) string {
	sum := sha256.Sum256([]byte(ssid))
	return networkPrefix + hex.EncodeToString(sum[:6]) + ".nmconnection"
}

// wifiUUID is stable per network, so a rewritten file stays the same connection.
func wifiUUID(ssid string) string {
	sum := sha256.Sum256([]byte("hauswart-wifi\x00" + ssid))
	h := hex.EncodeToString(sum[:16])
	return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:32]
}

// keyfileValue escapes a value for a NetworkManager keyfile, which reads it like
// a GLib key file.
func keyfileValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, "\r", `\r`, "\t", `\t`).Replace(s)
}

func wifiKeyfile(rule api.WifiRule) []byte {
	keyMgmt := "wpa-psk"
	if rule.Security == "wpa3" {
		keyMgmt = "sae"
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Managed by Hauswart\n[connection]\nid=%s\nuuid=%s\ntype=wifi\nautoconnect=true\n\n",
		keyfileValue(rule.SSID), wifiUUID(rule.SSID))
	fmt.Fprintf(&b, "[wifi]\nmode=infrastructure\nssid=%s\nhidden=%t\n\n", keyfileValue(rule.SSID), rule.Hidden)
	fmt.Fprintf(&b, "[wifi-security]\nkey-mgmt=%s\npsk=%s\n\n", keyMgmt, keyfileValue(rule.Password))
	b.WriteString("[ipv4]\nmethod=auto\n\n[ipv6]\nmethod=auto\n")
	return b.Bytes()
}

// enforceWifi writes a keyfile per network and removes its own that left the
// policy. NetworkManager reads them after a reload.
func (pe *PolicyEngine) enforceWifi(ctx context.Context, networks []api.WifiRule, o *outcome) {
	e := pe.exec
	dir := e.path(nmConnections)
	if len(networks) > 0 && e.Has != nil && !e.Has("nmcli") {
		o.deviate(deviationWifi, "NetworkManager", "NetworkManager is not installed")
		return
	}
	wanted := map[string][]byte{}
	for _, rule := range networks {
		wanted[wifiFile(rule.SSID)] = wifiKeyfile(rule)
	}
	changed := false
	if len(wanted) > 0 {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			o.deviate(deviationWifi, "NetworkManager", err)
			return
		}
	}
	for _, rule := range networks {
		name := wifiFile(rule.SSID)
		full := filepath.Join(dir, name)
		if current, err := os.ReadFile(full); err == nil && bytes.Equal(current, wanted[name]) {
			continue
		}
		if err := writeAtomic(full, wanted[name], 0o600); err != nil {
			o.deviate(deviationWifi, rule.SSID, err)
			continue
		}
		changed = true
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, networkPrefix) || !strings.HasSuffix(name, ".nmconnection") {
			continue
		}
		if _, ok := wanted[name]; ok {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			o.deviate(deviationWifi, name, err)
			continue
		}
		changed = true
	}
	if !changed {
		return
	}
	if e.Has == nil || e.Has("nmcli") {
		if out, err := e.Run(ctx, "nmcli", "connection", "reload"); err != nil {
			o.deviate(deviationWifi, "NetworkManager", fmt.Errorf("%w: %s", err, clip(out, maxDeviationText)))
			return
		}
	}
	o.corrected = append(o.corrected, "wifi")
}

// printerQueue is the CUPS queue of a printer.
func printerQueue(name string) string { return networkPrefix + name }

// cupsQueues lists the queues of CUPS with their device URI.
func (e *Executor) cupsQueues(ctx context.Context) (map[string]string, string, error) {
	out, err := e.Run(ctx, "lpstat", "-v")
	queues := map[string]string{}
	if err != nil {
		// lpstat fails when there is no queue at all.
		if strings.Contains(out, "No destinations") {
			return queues, "", nil
		}
		return nil, "", fmt.Errorf("%w: %s", err, clip(out, maxDeviationText))
	}
	for line := range strings.Lines(out) {
		// "device for NAME: URI"
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "device for ")
		if !ok {
			continue
		}
		name, uri, ok := strings.Cut(rest, ": ")
		if ok {
			queues[name] = uri
		}
	}
	current, _ := e.Run(ctx, "lpstat", "-d")
	defaultQueue := ""
	if _, after, ok := strings.Cut(current, "destination: "); ok {
		defaultQueue = strings.TrimSpace(after)
	}
	return queues, defaultQueue, nil
}

// enforcePrinters keeps a CUPS queue per printer, set up with IPP Everywhere,
// and removes its own queues that left the policy.
func (pe *PolicyEngine) enforcePrinters(ctx context.Context, printers []api.PrinterRule, o *outcome) {
	e := pe.exec
	if len(printers) == 0 && (e.Has == nil || !e.Has("lpstat")) {
		return
	}
	if e.Has != nil && (!e.Has("lpadmin") || !e.Has("lpstat")) {
		if len(printers) > 0 {
			o.deviate(deviationPrinter, "CUPS", "CUPS is not installed")
		}
		return
	}
	queues, defaultQueue, err := e.cupsQueues(ctx)
	if err != nil {
		if len(printers) > 0 {
			o.deviate(deviationPrinter, "CUPS", err)
		}
		return
	}
	changed := false
	var wantedDefault string
	for _, printer := range printers {
		queue := printerQueue(printer.Name)
		if printer.Default {
			wantedDefault = queue
		}
		if queues[queue] == printer.URI {
			continue
		}
		// IPP Everywhere asks the printer itself, so it has to answer now.
		if out, err := e.Run(ctx, "lpadmin", "-p", queue, "-E", "-v", printer.URI, "-m", "everywhere"); err != nil {
			o.deviate(deviationPrinter, printer.Name, fmt.Errorf("%w: %s", err, clip(out, maxDeviationText)))
			continue
		}
		changed = true
	}
	if wantedDefault != "" && defaultQueue != wantedDefault {
		if out, err := e.Run(ctx, "lpadmin", "-d", wantedDefault); err != nil {
			o.deviate(deviationPrinter, wantedDefault, fmt.Errorf("%w: %s", err, clip(out, maxDeviationText)))
		} else {
			changed = true
		}
	}
	names := make([]string, 0, len(printers))
	for _, printer := range printers {
		names = append(names, printerQueue(printer.Name))
	}
	for queue := range queues {
		if !strings.HasPrefix(queue, networkPrefix) || slices.Contains(names, queue) {
			continue
		}
		if out, err := e.Run(ctx, "lpadmin", "-x", queue); err != nil {
			o.deviate(deviationPrinter, queue, fmt.Errorf("%w: %s", err, clip(out, maxDeviationText)))
			continue
		}
		changed = true
	}
	if changed {
		o.corrected = append(o.corrected, "printers")
	}
}
