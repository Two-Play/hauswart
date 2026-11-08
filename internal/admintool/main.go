// Command hauswart-admin runs on the admin's own computer. It signs tasks, so
// that a compromised server alone cannot act on protected devices. Everything
// it knows from the server is treated as untrusted.
package admintool

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/GehirnInc/crypt/sha512_crypt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/pki"
	"github.com/Two-Play/hauswart/internal/sign"
)

const (
	sessionCookie    = "hauswart_session"
	signedLifetime   = 30 * 24 * time.Hour
	startPasswordLen = 20
	minimumKeys      = 2
	maxResponse      = 8 << 20

	// maxCounterJump is how far a device's reported counter may lie above the
	// local one. A device gets ahead when a second admin computer signs, or after
	// an old admin.json comes back, and a household will not sign a million tasks in
	// between. A hacked server gains little within it: skipped counters do no
	// harm, and using them all up would take 2^44 real signatures.
	maxCounterJump = 1 << 20
)

// device is what this tool knows on its own. The name was given here, and the
// counter continues from here, so neither depends on the server.
type device struct {
	Name    string `json:"name"`
	Counter uint64 `json:"counter"`
	// Passkeys are those pinned from this computer. keys.set replaces the whole
	// list, and the device does not say anything the server could not fake.
	Passkeys []sign.Passkey `json:"passkeys,omitempty"`
}

type config struct {
	Server      string             `json:"server"`
	Fingerprint string             `json:"ca_fingerprint"`
	CA          string             `json:"ca"`
	Session     string             `json:"session"`
	Keys        []string           `json:"keys"`
	Devices     map[string]*device `json:"devices"`
}

func configPath() (string, error) {
	if dir := os.Getenv("HAUSWART_ADMIN_DIR"); dir != "" {
		return filepath.Join(dir, "admin.json"), nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "hauswart", "admin.json"), nil
}

func loadConfig() (*config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	cfg := &config{Devices: map[string]*device{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, err
	}
	if cfg.Devices == nil {
		cfg.Devices = map[string]*device{}
	}
	return cfg, nil
}

// lockConfig keeps the terminal and the app from writing at once. A counter that
// goes backwards gets the next signature refused.
func lockConfig() (func(), error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return func() { file.Close() }, nil
}

// updateConfig changes what is on disk now, and not what was read a while ago.
func updateConfig(change func(*config)) error {
	unlock, err := lockConfig()
	if err != nil {
		return err
	}
	defer unlock()
	fresh, err := loadConfig()
	if err != nil {
		return err
	}
	change(fresh)
	return fresh.write()
}

func (c *config) save() error {
	unlock, err := lockConfig()
	if err != nil {
		return err
	}
	defer unlock()
	return c.write()
}

func (c *config) write() error {
	path, err := configPath()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	// The counters must never go backwards, even after a power cut.
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (c *config) client() (*http.Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(c.CA)) {
		return nil, errors.New("not logged in, run hauswart-admin login")
	}
	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}},
	}, nil
}

func (c *config) call(method, path string, body, out any) error {
	client, err := c.client()
	if err != nil {
		return err
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.Server+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hauswart", "1")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.Session})
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return errors.New("session expired, run hauswart-admin login")
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server said %d: %s", resp.StatusCode, clean(string(data)))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Main runs the command line tool.
func Main() {
	if len(os.Args) < 2 {
		usage()
	}
	commands := map[string]func([]string) error{
		"login":          login,
		"keys":           keys,
		"enroll-command": enrollCommand,
		"trust-command":  trustCommand,
		"devices":        devices,
		"name":           name,
		"approve":        approve,
		"start-password": startPassword,
		"rotate-keys":    rotateKeys,
		"passkeys":       passkeys,
		"terminal":       terminal,
	}
	command, ok := commands[os.Args[1]]
	if !ok {
		usage()
	}
	if err := command(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: hauswart-admin COMMAND

  login --server URL --ca-fingerprint F --user NAME
  keys add FILE...        pin public keys, at least two, one kept offline
  keys list
  enroll-command          print the command for a new protected device
  trust-command           print the command to protect an enrolled device
  devices                 list devices
  name ID NAME            name a device, which is needed before signing for it
  approve [--all]         review and sign waiting tasks; --all shows them all and asks once
  start-password --device ID --user NAME
  rotate-keys --device ID replace the keys pinned on a device
  passkeys list           show registered passkeys and what is pinned from here
  passkeys pin --device ID --passkey N
  passkeys unpin --device ID [--name NAME]
  passkeys renew --device ID
  terminal --device ID [--user NAME] [--minutes N]
                          sign and open a live shell, as root unless a user is given
`)
	os.Exit(2)
}

func login(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	server := fs.String("server", "", "server URL")
	fingerprint := fs.String("ca-fingerprint", "", "SHA-256 fingerprint of the server CA")
	user := fs.String("user", "admin", "dashboard user")
	fs.Parse(args)
	if *server == "" || *fingerprint == "" {
		return errors.New("--server and --ca-fingerprint are required")
	}
	insecure := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := insecure.Get(strings.TrimRight(*server, "/") + "/ca.pem")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	caPEM, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	ca, err := pki.ParseCert(caPEM)
	if err != nil {
		return err
	}
	if got := pki.Fingerprint(ca.Raw); !strings.EqualFold(got, *fingerprint) {
		return fmt.Errorf("CA fingerprint mismatch: got %s", got)
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	cfg.Server = strings.TrimRight(*server, "/")
	cfg.Fingerprint = *fingerprint
	cfg.CA = string(caPEM)
	password, err := readPassword()
	if err != nil {
		return err
	}
	return cfg.logIn(*user, password)
}

// logIn starts a session with the server that this config already trusts.
func (c *config) logIn(user, password string) error {
	client, err := c.client()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(map[string]string{"username": user, "password": password})
	if err != nil {
		return err
	}
	loginReq, err := http.NewRequest(http.MethodPost, c.Server+"/api/login", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("X-Hauswart", "1")
	loginResp, err := client.Do(loginReq)
	if err != nil {
		return err
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		return errors.New("login failed")
	}
	for _, cookie := range loginResp.Cookies() {
		if cookie.Name == sessionCookie {
			c.Session = cookie.Value
		}
	}
	return c.save()
}

func readPassword() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, "Password: ")
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(raw), err
}

func keys(args []string) error {
	if len(args) == 0 {
		usage()
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		for _, key := range cfg.Keys {
			fmt.Println(key)
		}
		return nil
	case "add":
		for _, file := range args[1:] {
			raw, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			key, err := sign.ParseKey(string(raw))
			if err != nil {
				return fmt.Errorf("%s: %w", file, err)
			}
			cfg.Keys = append(cfg.Keys, sign.FormatKey(key))
		}
		return cfg.save()
	}
	usage()
	return nil
}

func keyFlags(cfg *config) (string, error) {
	if len(cfg.Keys) < minimumKeys {
		return "", fmt.Errorf("pin at least %d keys first, so that losing one does not lock you out", minimumKeys)
	}
	var b strings.Builder
	for _, key := range cfg.Keys {
		fmt.Fprintf(&b, " --signing-key '%s'", key)
	}
	return b.String(), nil
}

// enrollCommand builds the command here. Only the token comes from the server:
// the admin pastes this as root, so the server must not supply the text.
func enrollCommand(_ []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	flags, err := keyFlags(cfg)
	if err != nil {
		return err
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := cfg.call("POST", "/api/enroll-tokens", struct{}{}, &out); err != nil {
		return err
	}
	raw, err := hex.DecodeString(out.Token)
	if err != nil || len(raw) != 32 {
		return errors.New("server sent an invalid token")
	}
	fmt.Printf("sudo hauswart-agent enroll --server '%s' --token %s --ca-fingerprint %s%s\n",
		cfg.Server, out.Token, cfg.Fingerprint, flags)
	return nil
}

func trustCommand(_ []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	flags, err := keyFlags(cfg)
	if err != nil {
		return err
	}
	fmt.Printf("sudo hauswart-agent trust-key%s\n", flags)
	return nil
}

type serverDevice struct {
	ID       string      `json:"id"`
	Hostname string      `json:"hostname"`
	Revoked  bool        `json:"revoked"`
	Report   *api.Report `json:"report"`
}

func fetchDevices(cfg *config) (map[string]serverDevice, error) {
	var list []serverDevice
	if err := cfg.call("GET", "/api/devices", nil, &list); err != nil {
		return nil, err
	}
	result := make(map[string]serverDevice, len(list))
	for _, d := range list {
		result[d.ID] = d
	}
	return result, nil
}

func devices(_ []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	list, err := fetchDevices(cfg)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(list))
	for id := range list {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		d := list[id]
		local := "(no name, run: hauswart-admin name " + id + " NAME)"
		if known := cfg.Devices[id]; known != nil && known.Name != "" {
			local = known.Name
		}
		protected := "not protected"
		if d.Report != nil && d.Report.Protected {
			protected = "protected"
		}
		fmt.Printf("%s  %s  %s  server calls it: %s\n", id, local, protected, clean(d.Hostname))
	}
	return nil
}

func name(args []string) error {
	if len(args) != 2 {
		usage()
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	known := cfg.Devices[args[0]]
	if known == nil {
		known = &device{}
		cfg.Devices[args[0]] = known
	}
	known.Name = args[1]
	return cfg.save()
}

func signer(cfg *config) (ssh.Signer, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, errors.New("no ssh-agent, SSH_AUTH_SOCK is not set")
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, err
	}
	signers, err := agent.NewClient(conn).Signers()
	if err != nil {
		return nil, err
	}
	for _, candidate := range signers {
		for _, key := range cfg.Keys {
			if sign.FormatKey(candidate.PublicKey()) == key {
				return candidate, nil
			}
		}
	}
	return nil, errors.New("none of the pinned keys is in the ssh-agent, add it with ssh-add -c")
}

// seal signs a task for a device and records the counter first: a counter must
// never be used twice, while a skipped one does no harm.
func seal(cfg *config, key ssh.Signer, id string, report *api.Report, taskType string, payload []byte, notAfter time.Time) (sign.Signed, error) {
	known := cfg.Devices[id]
	if known == nil || known.Name == "" {
		return sign.Signed{}, fmt.Errorf("device %s has no name here, check it and run hauswart-admin name", id)
	}
	counter, err := nextCounter(known.Counter, report)
	if err != nil {
		return sign.Signed{}, fmt.Errorf("device %s (%s): %w", known.Name, id, err)
	}
	// Only the counter is written, on top of what is on disk by now.
	err = updateConfig(func(fresh *config) {
		stored := fresh.Devices[id]
		if stored == nil {
			stored = &device{Name: known.Name}
			fresh.Devices[id] = stored
		}
		counter = max(counter, stored.Counter+1)
		stored.Counter = counter
	})
	if err != nil {
		return sign.Signed{}, err
	}
	known.Counter = counter
	return sign.Sign(key, sign.Envelope{
		Type:     taskType,
		Payload:  payload,
		DeviceID: id,
		Counter:  known.Counter,
		NotAfter: notAfter,
	})
}

// nextCounter picks the counter for the next signature. The report comes through
// the server, so it may only move the counter forward by a plausible distance.
func nextCounter(local uint64, report *api.Report) (uint64, error) {
	counter := local
	if report != nil && report.Counter > local {
		if report.Counter-local > maxCounterJump {
			return 0, fmt.Errorf("refusing the counter %d from the server, it is more than %d above the one here, %d: "+
				"the server may be hacked, or this admin.json is very old. If the device really is that far ahead, "+
				"copy the counter from your newest admin.json", report.Counter, maxCounterJump, local)
		}
		counter = report.Counter
	}
	if counter == math.MaxUint64 {
		return 0, errors.New("the counter is used up, enroll the device again")
	}
	return counter + 1, nil
}

func signedUntil(taskType string, payload []byte) time.Time {
	if window := api.ApprovalWindow(taskType); window > 0 {
		return time.Now().Add(window * 2 / 3)
	}
	if deadline, ok := actionDeadline(taskType, payload); ok {
		return deadline
	}
	if taskType == api.TaskSudoGrant {
		var p api.SudoGrantPayload
		if json.Unmarshal(payload, &p) == nil {
			return p.ExpiresAt
		}
	}
	return time.Now().Add(signedLifetime)
}

type queued struct {
	ID        string          `json:"id"`
	DeviceID  string          `json:"device_id"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
	CreatedBy string          `json:"created_by"`
}

func approve(args []string) error {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	all := fs.Bool("all", false, "show every waiting task, then sign them all after one question")
	fs.Parse(args)
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	var queue []queued
	if err := cfg.call("GET", "/api/signing", nil, &queue); err != nil {
		return err
	}
	if len(queue) == 0 {
		fmt.Println("Nothing is waiting for a signature.")
		return nil
	}
	key, err := signer(cfg)
	if err != nil {
		return err
	}
	list, err := fetchDevices(cfg)
	if err != nil {
		return err
	}
	input := bufio.NewReader(os.Stdin)
	if *all {
		return approveAll(cfg, key, list, queue, input)
	}
	// Policies that were accepted for every device they are queued for.
	acceptedPolicies := map[string]bool{}
	for i, task := range queue {
		fmt.Printf("\n[%d/%d] requested through %s\n", i+1, len(queue), clean(task.CreatedBy))
		item := prepare(cfg, list, task, queue[i+1:])
		if item.Problem != "" {
			fmt.Printf("  %s\n", item.Problem)
			continue
		}
		answer := "y"
		if item.Group != "" && acceptedPolicies[item.Group] {
			fmt.Printf("  Device: %s (%s)\n  Same policy as accepted above.\n", item.DeviceName, task.DeviceID)
		} else {
			fmt.Printf("  Device: %s (%s)\n  %s\n", item.DeviceName, task.DeviceID, item.Text)
			prompt := "Sign? [y/N/r to reject] "
			if item.Group != "" {
				fmt.Println(item.Changes)
				if item.Warning != "" {
					fmt.Println(item.Warning)
				}
				if len(item.Others) > 0 {
					fmt.Printf("  The same policy waits for other devices:\n%s\n", strings.Join(item.Others, "\n"))
					prompt = "Sign? [y/N/a for all of these/r to reject] "
				}
			}
			fmt.Print(prompt)
			line, err := input.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			answer = strings.ToLower(strings.TrimSpace(line))
		}
		if answer == "a" && item.Group != "" {
			acceptedPolicies[item.Group] = true
			answer = "y"
		}
		switch answer {
		case "y":
			if err := signItem(cfg, key, list, item); err != nil {
				return err
			}
			fmt.Println("Signed.")
		case "r":
			if err := cfg.call("POST", "/api/tasks/"+task.ID+"/reject", struct{}{}, nil); err != nil {
				return err
			}
			fmt.Println("Rejected.")
		default:
			fmt.Println("Left in the queue.")
		}
	}
	return nil
}

// approveAll shows every waiting task in full and asks once. What cannot be
// signed is shown with its reason and stays in the queue.
func approveAll(cfg *config, key ssh.Signer, list map[string]serverDevice, queue []queued, input *bufio.Reader) error {
	var items []Item
	for i, task := range queue {
		item := prepare(cfg, list, task, queue[i+1:])
		fmt.Printf("\n[%d/%d] requested through %s\n", i+1, len(queue), clean(task.CreatedBy))
		if item.Problem != "" {
			fmt.Printf("  %s\n  Left in the queue.\n", item.Problem)
			continue
		}
		fmt.Printf("  Device: %s (%s)\n  %s\n", item.DeviceName, task.DeviceID, item.Text)
		if item.Changes != "" {
			fmt.Println(item.Changes)
		}
		if item.Warning != "" {
			fmt.Println(item.Warning)
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return nil
	}
	fmt.Printf("\nSign all %d tasks above? [y/N] ", len(items))
	line, err := input.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if strings.ToLower(strings.TrimSpace(line)) != "y" {
		fmt.Println("Left in the queue.")
		return nil
	}
	for _, item := range items {
		if err := signItem(cfg, key, list, item); err != nil {
			return err
		}
	}
	fmt.Printf("Signed %d tasks.\n", len(items))
	return nil
}

func deviceFlag(fs *flag.FlagSet, args []string, id *string) error {
	fs.Parse(args)
	if *id == "" {
		return errors.New("--device is required")
	}
	return nil
}

// startPassword creates the password here. If the server made it, it could
// hand over the hash of a password it knows, and a signature would approve it.
func startPassword(args []string) error {
	fs := flag.NewFlagSet("start-password", flag.ExitOnError)
	id := fs.String("device", "", "device ID")
	user := fs.String("user", "", "Linux user")
	if err := deviceFlag(fs, args, id); err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	key, err := signer(cfg)
	if err != nil {
		return err
	}
	list, err := fetchDevices(cfg)
	if err != nil {
		return err
	}
	raw := make([]byte, startPasswordLen/2)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	password := hex.EncodeToString(raw)
	hash, err := sha512_crypt.New().Generate([]byte(password), nil)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(api.PasswordPayload{User: *user, Hash: hash})
	if err != nil {
		return err
	}
	if err := api.Validate(api.TaskUserPassword, payload); err != nil {
		return err
	}
	signed, err := seal(cfg, key, *id, list[*id].Report, api.TaskUserPassword, payload, time.Now().Add(signedLifetime))
	if err != nil {
		return err
	}
	body := map[string]any{"type": api.TaskUserPassword, "signed": signed}
	var out struct {
		ID string `json:"id"`
	}
	if err := cfg.call("POST", "/api/devices/"+*id+"/signed-tasks", body, &out); err != nil {
		return err
	}
	fmt.Printf("Start password for %s: %s\nIt is shown only here and must be changed at the first login.\n", *user, password)
	return nil
}

func rotateKeys(args []string) error {
	fs := flag.NewFlagSet("rotate-keys", flag.ExitOnError)
	id := fs.String("device", "", "device ID")
	if err := deviceFlag(fs, args, id); err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	key, err := signer(cfg)
	if err != nil {
		return err
	}
	list, err := fetchDevices(cfg)
	if err != nil {
		return err
	}
	// keys.set replaces the passkeys too. admin.json is per computer, so an older
	// copy could bring back one that was removed: say what is about to happen.
	var pins []sign.Passkey
	if known := cfg.Devices[*id]; known != nil {
		pins = known.Passkeys
	}
	if len(pins) > 0 {
		fmt.Println("These passkeys stay pinned on the device:")
		for _, p := range pins {
			fmt.Println(describePasskey(p))
		}
		ok, err := confirm(os.Stdin, "Sign?")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("nothing changed")
		}
	}
	payload, err := json.Marshal(api.KeysPayload{Keys: cfg.Keys, Passkeys: pins})
	if err != nil {
		return err
	}
	signed, err := seal(cfg, key, *id, list[*id].Report, api.TaskKeysSet, payload, time.Now().Add(signedLifetime))
	if err != nil {
		return err
	}
	return cfg.call("POST", "/api/devices/"+*id+"/signed-tasks", map[string]any{"type": api.TaskKeysSet, "signed": signed}, nil)
}
