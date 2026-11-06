package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Two-Play/hauswart/internal/admintool"
	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/sign"
)

// adminSession is the desktop app's way in, against a real server and a real
// ssh-agent, which only the window is missing from.
func adminSession(t *testing.T, e *env, client *http.Client, device string) *admintool.Session {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	socket := filepath.Join(dir, "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(keyring, conn)
		}
	}()
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse(e.ts.URL)
	session := ""
	for _, cookie := range client.Jar.Cookies(target) {
		if cookie.Name == sessionCookie {
			session = cookie.Value
		}
	}
	cfg := map[string]any{
		"server": e.ts.URL, "session": session, "keys": []string{sign.FormatKey(signer.PublicKey())},
		"ca":      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.ca.Cert.Raw})),
		"devices": map[string]any{device: map[string]any{"name": "laptop"}},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "admin.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HAUSWART_ADMIN_DIR", dir)
	t.Setenv("SSH_AUTH_SOCK", socket)
	s, err := admintool.Open()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDesktopAppSignsThroughARealServer(t *testing.T) {
	e := setup(t)
	device, agentClient := protectedDevice(t, e)
	admin := e.login("admin")
	session := adminSession(t, e, admin, device)
	in := map[string]any{"type": api.TaskPkgInstall, "payload": api.PackagesPayload{Packages: []string{"vim"}}}
	if code, data := e.do(admin, "POST", "/api/devices/"+device+"/tasks", in); code != http.StatusCreated {
		t.Fatalf("%d %s", code, data)
	}
	items, err := session.Items()
	if err != nil || len(items) != 1 || !strings.Contains(items[0].Text, "vim") || items[0].DeviceName != "laptop" {
		t.Fatalf("%+v, %v", items, err)
	}
	if err := session.Sign(items[0]); err != nil {
		t.Fatal(err)
	}
	code, data := e.do(agentClient, "GET", "/agent/tasks?wait=0", nil)
	if code != http.StatusOK || !strings.Contains(string(data), `"signed"`) {
		t.Fatalf("%d %s", code, data)
	}
	if err := session.Sign(items[0]); !errors.Is(err, admintool.ErrChanged) {
		t.Fatalf("signed twice: %v", err)
	}
}

// What a hacked server does while the admin is reading.
func TestDesktopAppRefusesATaskSwappedOnTheServer(t *testing.T) {
	e := setup(t)
	device, _ := protectedDevice(t, e)
	admin := e.login("admin")
	session := adminSession(t, e, admin, device)
	in := map[string]any{"type": api.TaskPkgInstall, "payload": api.PackagesPayload{Packages: []string{"vim"}}}
	if code, data := e.do(admin, "POST", "/api/devices/"+device+"/tasks", in); code != http.StatusCreated {
		t.Fatalf("%d %s", code, data)
	}
	items, err := session.Items()
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE tasks SET payload = '{"packages":["evil"]}' WHERE id = ?`, items[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := session.Sign(items[0]); !errors.Is(err, admintool.ErrChanged) {
		t.Fatalf("got %v", err)
	}
}
