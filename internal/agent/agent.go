// Package agent is the device side: enrollment, the connection to the server
// and the execution of tasks.
package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/pki"
	"github.com/Two-Play/hauswart/internal/sign"
)

const (
	configFile     = "agent.json"
	keyFile        = "agent-key.pem"
	certFile       = "agent.pem"
	caFile         = "ca.pem"
	grantsFile     = "grants.json"
	guardFile      = "guard.json"
	reportInterval = time.Minute
	grantInterval  = 15 * time.Second
	pollWaitSecs   = 25
	retryDelay     = 10 * time.Second
	maxResponse    = 8 << 20

	// A device renews once a third of its certificate's lifetime is left. At
	// two years, that tolerates eight months switched off.
	renewShare       = 3
	maxRenewInterval = time.Hour
	minRenewInterval = time.Second
)

// DefaultAllowedPaths is deliberately narrow: no location from which the
// system would execute a file. Widen it per device in agent.json.
var DefaultAllowedPaths = []string{"/etc/hauswart.d"}

type Config struct {
	Server       string   `json:"server"`
	DeviceID     string   `json:"device_id"`
	AllowedPaths []string `json:"allowed_paths"`
	// SigningKeys are the public keys tasks must be signed with. The server
	// has no way to change them. Empty means this device is not protected.
	SigningKeys []string `json:"signing_keys,omitempty"`
	// Passkeys may approve tasks in a browser. Like the keys, they only arrive
	// through a signed keys.set.
	Passkeys []sign.Passkey `json:"passkeys,omitempty"`
	// PasskeyTypes limits what a passkey may approve on this device. It is the
	// device owner's: no task changes it, and the agent reads it at start. null
	// means api.DefaultPasskeyTypes, an empty list means nothing at all, so this
	// field must never get omitempty.
	PasskeyTypes []string `json:"passkey_types"`
}

// passkeyTypes applies the default.
func (c Config) passkeyTypes() []string {
	if c.PasskeyTypes == nil {
		return api.DefaultPasskeyTypes
	}
	return c.PasskeyTypes
}

// DeviceID reads the ID of an enrolled device.
func DeviceID(dir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		return "", err
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", err
	}
	return cfg.DeviceID, nil
}

// TrustKeys pins signing keys on a device that has none yet, which needs root
// on the device. Afterwards, a signed keys.set is the way to change them.
func TrustKeys(dir string, keys []string) error {
	if len(keys) == 0 {
		return errors.New("no keys given")
	}
	for _, key := range keys {
		if _, err := sign.ParseKey(key); err != nil {
			return err
		}
	}
	path := filepath.Join(dir, configFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("not enrolled: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	if len(cfg.SigningKeys) > 0 {
		return errors.New("signing keys are already pinned, use a signed keys.set task")
	}
	if err := CreateGuard(filepath.Join(dir, guardFile)); err != nil {
		return err
	}
	cfg.SigningKeys = keys
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicSync(path, out, 0o600)
}

// Enroll registers this device. The CA is fetched over an unverified
// connection and accepted only if it matches the pinned fingerprint, so the
// fingerprint in the enroll command is what the whole trust rests on.
func Enroll(ctx context.Context, dir, serverURL, token, fingerprint string, signingKeys []string) error {
	serverURL = strings.TrimRight(serverURL, "/")
	if !strings.HasPrefix(serverURL, "https://") {
		return errors.New("server URL must use https")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, key := range signingKeys {
		if _, err := sign.ParseKey(key); err != nil {
			return err
		}
	}
	insecure := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	caPEM, err := fetch(ctx, insecure, serverURL+"/ca.pem")
	if err != nil {
		return fmt.Errorf("fetching CA: %w", err)
	}
	ca, err := pki.ParseCert(caPEM)
	if err != nil {
		return err
	}
	if got := pki.Fingerprint(ca.Raw); !strings.EqualFold(got, fingerprint) {
		return fmt.Errorf("CA fingerprint mismatch: got %s", got)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	pinned := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}},
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "hauswart-agent"}}, key)
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	body, err := json.Marshal(api.EnrollRequest{
		Token:    token,
		CSR:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		Hostname: hostname,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/agent/enroll", bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp, err := pinned.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enrollment refused: %s", strings.TrimSpace(string(data)))
	}
	var out api.EnrollResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	// The ID belongs to this key. A server that hands out another one could
	// reuse the identity of an earlier installation.
	wantID, err := pki.DeviceID(&key.PublicKey)
	if err != nil {
		return err
	}
	if out.DeviceID != wantID {
		return fmt.Errorf("server assigned device ID %q, expected %q", out.DeviceID, wantID)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if len(signingKeys) > 0 {
		if err := CreateGuard(filepath.Join(dir, guardFile)); err != nil {
			return err
		}
	}
	cfg, err := json.MarshalIndent(Config{
		Server:       serverURL,
		DeviceID:     out.DeviceID,
		AllowedPaths: DefaultAllowedPaths,
		SigningKeys:  signingKeys,
		PasskeyTypes: api.DefaultPasskeyTypes,
	}, "", "  ")
	if err != nil {
		return err
	}
	for name, content := range map[string][]byte{keyFile: keyPEM, certFile: []byte(out.Cert), caFile: caPEM, configFile: cfg} {
		if err := writeAtomic(filepath.Join(dir, name), content, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// TrustServerCA adds the server's CA to the system store, so that browsers on
// this device open the dashboard without a warning. This grants the server
// nothing new, because it can deploy certificates with ca.install anyway.
func TrustServerCA(ctx context.Context, dir string) error {
	caPEM, err := os.ReadFile(filepath.Join(dir, caFile))
	if err != nil {
		return err
	}
	e := &Executor{Root: "/", Platform: Detect(), Run: RunCommand}
	_, err = e.caInstall(ctx, api.CAInstallPayload{Name: "server", PEM: string(caPEM)})
	return err
}

func fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// Agent is the running service.
type Agent struct {
	cfg      Config
	dir      string
	client   *http.Client
	exec     *Executor
	platform Platform
	log      *slog.Logger

	mu   sync.RWMutex
	cert tls.Certificate
	leaf *x509.Certificate
	pool *x509.CertPool

	// guard is nil on a device without pinned keys.
	guard *Guard
	// policy keeps this device in the state its admin signed.
	policy *PolicyEngine
	// notices tell people at the device what changed for them.
	notices *Notices
	// access blocks the device for some or all of its people.
	access *Access
	// requestsChanged asks for the state of requests now, after one was filed.
	requestsChanged chan struct{}
	// terminals are the live shells that run.
	terminals terminals
}

// Load reads the enrolled state from dir.
func Load(dir string, log *slog.Logger) (*Agent, error) {
	raw, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		return nil, fmt.Errorf("not enrolled: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, certFile), filepath.Join(dir, keyFile))
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, caFile))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid CA file")
	}
	grants, err := OpenGrants(filepath.Join(dir, grantsFile))
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	var guard *Guard
	if len(cfg.SigningKeys) > 0 {
		if guard, err = OpenGuard(filepath.Join(dir, guardFile), cfg.SigningKeys); err != nil {
			return nil, err
		}
		guard.SetPasskeys(usablePasskeys(cfg.Passkeys, log), cfg.passkeyTypes())
	}
	platform := Detect()
	a := &Agent{
		guard: guard,
		cfg:   cfg,
		dir:   dir,
		cert:  cert,
		leaf:  leaf,
		pool:  pool,
		exec: &Executor{
			Root:         "/",
			AllowedPaths: cfg.AllowedPaths,
			Platform:     platform,
			Grants:       grants,
			Run:          RunCommand,
			RunInput:     RunCommandInput,
			Has:          func(name string) bool { _, err := exec.LookPath(name); return err == nil },
		},
		platform: platform,
		log:      log,
	}
	a.policy = OpenPolicy(dir, a.exec, log)
	a.notices = OpenNotices(dir, a.exec, a.policy.Language, log)
	// GNOME reads the folder of Flatpak apps at login only, so people who are
	// logged in need to hear why a new app is missing from their menu.
	a.exec.FlatpakArrived = func() {
		a.notices.record(context.Background(), api.DeviceEvent{Kind: api.EventFlatpakArrived}, urgencyNormal)
	}
	a.access = OpenAccess(dir, a.exec, a.notices, log)
	a.requestsChanged = make(chan struct{}, 1)
	a.client = &http.Client{
		Timeout: (pollWaitSecs + 15) * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13,
			// Asked on every handshake, so a renewed certificate takes effect
			// without restarting the agent.
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				a.mu.RLock()
				defer a.mu.RUnlock()
				return &a.cert, nil
			},
		}},
	}
	return a, nil
}

// usablePasskeys drops what does not parse. A bad entry costs that one passkey
// and must never stop the agent, because then signed tasks would stop as well.
func usablePasskeys(passkeys []sign.Passkey, log *slog.Logger) []sign.Passkey {
	usable := make([]sign.Passkey, 0, len(passkeys))
	for _, p := range passkeys {
		if err := sign.ValidPasskey(p); err != nil {
			log.Warn("ignoring pinned passkey", "name", p.Name, "err", err)
			continue
		}
		usable = append(usable, p)
	}
	return usable
}

// Run blocks until ctx ends.
func (a *Agent) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Go(func() { a.grantLoop(ctx) })
	wg.Go(func() { a.reportLoop(ctx) })
	wg.Go(func() { a.taskLoop(ctx) })
	wg.Go(func() { a.renewLoop(ctx) })
	wg.Go(func() { a.updateLoop(ctx) })
	wg.Go(func() { a.inventoryLoop(ctx) })
	wg.Go(func() { a.catalogLoop(ctx) })
	wg.Go(func() { a.policy.Loop(ctx) })
	wg.Go(func() { a.policy.ScreenLoop(ctx) })
	wg.Go(func() { a.serveUsers(ctx, userSocket) })
	wg.Go(func() { a.requestLoop(ctx) })
	wg.Go(func() { a.access.Loop(ctx) })
	wg.Wait()
}

func renewDue(leaf *x509.Certificate, now time.Time) bool {
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	return leaf.NotAfter.Sub(now) < lifetime/renewShare
}

func renewInterval(leaf *x509.Certificate) time.Duration {
	return min(max(leaf.NotAfter.Sub(leaf.NotBefore)/20, minRenewInterval), maxRenewInterval)
}

func (a *Agent) renewLoop(ctx context.Context) {
	for {
		a.mu.RLock()
		leaf := a.leaf
		a.mu.RUnlock()
		if renewDue(leaf, time.Now()) {
			if err := a.renew(ctx); err != nil && ctx.Err() == nil {
				a.log.Warn("certificate renewal failed, will retry", "err", err, "expires", leaf.NotAfter)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(renewInterval(leaf)):
		}
	}
}

// renew keeps the private key and replaces only the certificate. That is one
// atomic rename, so a crash cannot leave a key and certificate that do not
// belong together.
func (a *Agent) renew(ctx context.Context) error {
	a.mu.RLock()
	current := a.cert
	a.mu.RUnlock()

	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "hauswart-agent"}}, current.PrivateKey)
	if err != nil {
		return err
	}
	body, err := json.Marshal(api.RenewRequest{CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.Server+"/agent/renew", bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	var out api.RenewResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(&out); err != nil {
		return err
	}

	leaf, err := pki.ParseCert([]byte(out.Cert))
	if err != nil {
		return err
	}
	opts := x509.VerifyOptions{Roots: a.pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("renewed certificate: %w", err)
	}
	if leaf.Subject.CommonName != a.cfg.DeviceID {
		return fmt.Errorf("renewed certificate is for %q", leaf.Subject.CommonName)
	}
	if err := writeAtomic(filepath.Join(a.dir, certFile), []byte(out.Cert), 0o600); err != nil {
		return err
	}
	a.mu.Lock()
	a.cert = tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: current.PrivateKey}
	a.leaf = leaf
	a.mu.Unlock()
	// Existing connections keep the old certificate until they are replaced.
	a.client.CloseIdleConnections()
	a.log.Info("certificate renewed", "expires", leaf.NotAfter)
	return nil
}

func (a *Agent) grantLoop(ctx context.Context) {
	ticker := time.NewTicker(grantInterval)
	defer ticker.Stop()
	for {
		// Runs immediately on start, so grants that expired while the device
		// was off are gone before anything else happens.
		revoked, err := a.exec.RevokeExpired()
		if err != nil {
			a.log.Error("revoking expired sudo grants failed", "err", err)
		}
		a.notices.CheckGrants(ctx, a.exec.Grants.All(), revoked)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *Agent) reportLoop(ctx context.Context) {
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()
	for {
		report := Collect(a.platform)
		report.Insight = a.exec.collectInsight(ctx)
		report.Policy = a.policy.Status()
		report.Apps = a.policy.Apps()
		if a.access != nil {
			report.Access = a.access.Current()
		}
		if a.guard != nil {
			report.Protected = true
			report.Counter = a.guard.Counter()
			report.PasskeyCounter = a.guard.PasskeyCounter()
			freshness, err := a.guard.Freshness(time.Now())
			if err != nil {
				a.log.Error("saving signing state failed", "err", err)
			}
			report.PasskeyFreshness = freshness
			report.Passkeys, report.PasskeyTypes = a.guard.Passkeys()
			if err := a.guard.Touch(time.Now()); err != nil {
				a.log.Error("saving signing state failed", "err", err)
			}
		}
		if err := a.post(ctx, "/agent/report", report); err != nil && ctx.Err() == nil {
			a.log.Warn("report failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// errSuspended says that the server holds this device back.
var errSuspended = errors.New("this device is suspended")

// suspendedRetry is how often a suspended device asks whether it is back.
const suspendedRetry = 30 * time.Second

func (a *Agent) taskLoop(ctx context.Context) {
	for ctx.Err() == nil {
		task, err := a.poll(ctx)
		if errors.Is(err, errSuspended) {
			a.suspend(ctx)
			select {
			case <-ctx.Done():
			case <-time.After(suspendedRetry):
			}
			continue
		}
		if err == nil && a.notices.SetSuspended(ctx, false) {
			a.log.Info("the server manages this device again")
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			a.log.Warn("poll failed", "err", err)
			select {
			case <-ctx.Done():
			case <-time.After(retryDelay):
			}
			continue
		}
		if task == nil {
			continue
		}
		result := a.handle(ctx, *task)
		a.log.Info("task finished", "id", task.ID, "ok", result.OK)
		if err := a.post(ctx, "/agent/tasks/"+task.ID+"/result", result); err != nil {
			a.log.Error("sending result failed", "id", task.ID, "err", err)
		}
	}
}

// handle runs a task after the guard admitted it. On a protected device, the
// guard replaces what the server sent with what the admin signed, and that is
// also what people are told about.
func (a *Agent) handle(ctx context.Context, task api.Task) api.TaskResult {
	if a.guard != nil {
		admitted, err := a.guard.Admit(task, a.cfg.DeviceID, time.Now())
		if err != nil {
			a.log.Warn("task refused", "id", task.ID, "err", err)
			return api.TaskResult{OK: false, Output: "refused: " + err.Error()}
		}
		task = admitted
	}
	result := a.run(ctx, task)
	if a.notices != nil {
		a.notices.AfterTask(ctx, task, result)
	}
	return result
}

func (a *Agent) run(ctx context.Context, task api.Task) api.TaskResult {
	if task.Approver != "" {
		// The server's audit log proves nothing, so this is the record that
		// counts of what an approval in a browser really did.
		a.log.Warn("running task approved by passkey", "id", task.ID, "type", task.Type,
			"passkey", task.Approver, "payload", string(task.Payload))
	}
	a.log.Info("running task", "id", task.ID, "type", task.Type)
	switch task.Type {
	case api.TaskKeysSet:
		return a.setKeys(task)
	case api.TaskPolicySet, api.TaskPolicyClear:
		return a.setPolicy(task)
	case api.TaskScreenExtend:
		return a.extendScreenTime(task)
	case api.TaskAccessSet:
		if a.access == nil {
			return api.TaskResult{OK: false, Output: "access is not available"}
		}
		return a.access.Set(ctx, task)
	case api.TaskTerminalOpen:
		return a.openTerminal(ctx, task)
	}
	return a.exec.Execute(ctx, task)
}

// setKeys is only reachable through the guard: without pinned keys there is
// nothing to replace, and a server must not be able to pin its own.
func (a *Agent) setKeys(task api.Task) api.TaskResult {
	if a.guard == nil {
		return api.TaskResult{OK: false, Output: "this device has no pinned keys"}
	}
	if err := api.Validate(task.Type, task.Payload); err != nil {
		return api.TaskResult{OK: false, Output: err.Error()}
	}
	var p api.KeysPayload
	if err := json.Unmarshal(task.Payload, &p); err != nil {
		return api.TaskResult{OK: false, Output: err.Error()}
	}
	keys := make([]ssh.PublicKey, 0, len(p.Keys))
	for _, line := range p.Keys {
		key, err := sign.ParseKey(line)
		if err != nil {
			return api.TaskResult{OK: false, Output: err.Error()}
		}
		keys = append(keys, key)
	}
	// The file is read again, because the device owner may have edited it while
	// the agent runs. Only the two pinned lists come from the task.
	path := filepath.Join(a.dir, configFile)
	var cfg Config
	raw, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(raw, &cfg)
	}
	if err != nil {
		return api.TaskResult{OK: false, Output: err.Error()}
	}
	cfg.SigningKeys = p.Keys
	cfg.Passkeys = p.Passkeys
	raw, err = json.MarshalIndent(cfg, "", "  ")
	if err == nil {
		err = writeAtomicSync(path, raw, 0o600)
	}
	if err != nil {
		return api.TaskResult{OK: false, Output: err.Error()}
	}
	a.cfg = cfg
	a.guard.SetKeys(keys)
	a.guard.SetPasskeys(usablePasskeys(p.Passkeys, a.log), cfg.passkeyTypes())
	return api.TaskResult{OK: true, Output: fmt.Sprintf("%d signing keys and %d passkeys pinned", len(keys), len(p.Passkeys))}
}

func (a *Agent) poll(ctx context.Context) (*api.Task, error) {
	url := fmt.Sprintf("%s/agent/tasks?wait=%d", a.cfg.Server, pollWaitSecs)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusLocked:
		return nil, errSuspended
	case http.StatusOK:
		var t api.Task
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(&t); err != nil {
			return nil, err
		}
		return &t, nil
	}
	return nil, fmt.Errorf("status %d", resp.StatusCode)
}

func (a *Agent) post(ctx context.Context, path string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.Server+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// requestLoop asks how the requests of this device stand while someone is at a
// desktop to be told, and when someone filed one or looks at their history.
func (a *Agent) requestLoop(ctx context.Context) {
	ticker := time.NewTicker(requestInterval)
	defer ticker.Stop()
	asked := false
	for {
		if asked || a.someoneAtDesktop(ctx) {
			a.notices.Asked()
			var requests []api.RequestState
			if err := a.get(ctx, "/agent/requests", &requests); err != nil {
				if ctx.Err() == nil {
					a.log.Warn("asking for the state of requests failed", "err", err)
				}
			} else {
				a.notices.SetRequests(ctx, requests)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			asked = false
		case <-a.requestsChanged:
			asked = true
		}
	}
}

func (a *Agent) someoneAtDesktop(ctx context.Context) bool {
	people, err := a.exec.desktopUsers(ctx)
	return err == nil && len(people) > 0
}

// askForRequests wakes the request loop, unless it is busy already.
func (a *Agent) askForRequests() {
	select {
	case a.requestsChanged <- struct{}{}:
	default:
	}
}

// get reads a JSON answer of the server.
func (a *Agent) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Server+path, nil)
	if err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(v)
}

// suspend ends the sudo grants once, when the server starts to hold the device
// back: whoever grants them is not looking after this device for now.
func (a *Agent) suspend(ctx context.Context) {
	if a.notices.SetSuspended(ctx, true) {
		a.log.Warn("the server suspended this device")
	}
	// Every time, not only at the start: a revoke that failed, or a crash between
	// noting the suspension and revoking, must not leave a grant in place.
	for user := range a.exec.Grants.All() {
		if _, err := a.exec.sudoRevoke(user); err != nil {
			a.log.Error("ending a sudo grant failed", "user", user, "err", err)
		}
	}
}
