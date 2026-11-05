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
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/philippe/hauswart/internal/api"
	"github.com/philippe/hauswart/internal/pki"
)

const (
	configFile     = "agent.json"
	keyFile        = "agent-key.pem"
	certFile       = "agent.pem"
	caFile         = "ca.pem"
	grantsFile     = "grants.json"
	reportInterval = time.Minute
	grantInterval  = 15 * time.Second
	pollWaitSecs   = 25
	retryDelay     = 10 * time.Second
)

// DefaultAllowedPaths is deliberately narrow: no location from which the
// system would execute a file. Widen it per device in agent.json.
var DefaultAllowedPaths = []string{"/etc/hauswart.d"}

type Config struct {
	Server       string   `json:"server"`
	DeviceID     string   `json:"device_id"`
	AllowedPaths []string `json:"allowed_paths"`
}

// Enroll registers this device. The CA is fetched over an unverified
// connection and accepted only if it matches the pinned fingerprint, so the
// fingerprint in the enroll command is what the whole trust rests on.
func Enroll(ctx context.Context, dir, serverURL, token, fingerprint string) error {
	serverURL = strings.TrimRight(serverURL, "/")
	if !strings.HasPrefix(serverURL, "https://") {
		return errors.New("server URL must use https")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
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
	data, err := io.ReadAll(resp.Body)
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

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cfg, err := json.MarshalIndent(Config{Server: serverURL, DeviceID: out.DeviceID, AllowedPaths: DefaultAllowedPaths}, "", "  ")
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
	client   *http.Client
	exec     *Executor
	platform Platform
	log      *slog.Logger
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
	platform := Detect()
	return &Agent{
		cfg: cfg,
		client: &http.Client{
			Timeout: (pollWaitSecs + 15) * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs:      pool,
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
			}},
		},
		exec: &Executor{
			Root:         "/",
			AllowedPaths: cfg.AllowedPaths,
			Platform:     platform,
			Grants:       grants,
			Run:          RunCommand,
			RunInput:     RunCommandInput,
		},
		platform: platform,
		log:      log,
	}, nil
}

// Run blocks until ctx ends.
func (a *Agent) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Go(func() { a.grantLoop(ctx) })
	wg.Go(func() { a.reportLoop(ctx) })
	wg.Go(func() { a.taskLoop(ctx) })
	wg.Wait()
}

func (a *Agent) grantLoop(ctx context.Context) {
	ticker := time.NewTicker(grantInterval)
	defer ticker.Stop()
	for {
		// Runs immediately on start, so grants that expired while the device
		// was off are gone before anything else happens.
		if err := a.exec.RevokeExpired(); err != nil {
			a.log.Error("revoking expired sudo grants failed", "err", err)
		}
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
		if err := a.post(ctx, "/agent/report", Collect(a.platform)); err != nil && ctx.Err() == nil {
			a.log.Warn("report failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *Agent) taskLoop(ctx context.Context) {
	for ctx.Err() == nil {
		task, err := a.poll(ctx)
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
		a.log.Info("running task", "id", task.ID, "type", task.Type)
		result := a.exec.Execute(ctx, *task)
		a.log.Info("task finished", "id", task.ID, "ok", result.OK)
		if err := a.post(ctx, "/agent/tasks/"+task.ID+"/result", result); err != nil {
			a.log.Error("sending result failed", "id", task.ID, "err", err)
		}
	}
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
	case http.StatusOK:
		var t api.Task
		if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
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
