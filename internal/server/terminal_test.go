package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/sign"
)

type openedTerminal struct {
	ID      string `json:"id"`
	Session string `json:"session"`
}

// openTerminal asks for a session on a protected device, signs it with a
// stand-in signature and lets the device claim it, as a real one would.
func openTerminal(t *testing.T, e *env) (string, *http.Client, *http.Client, openedTerminal) {
	t.Helper()
	id, agent := e.enroll()
	protect(t, e, agent)
	admin := e.login("admin")
	code, data := e.do(admin, "POST", "/api/devices/"+id+"/terminal", map[string]any{"user": "root", "minutes": 5})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, data)
	}
	var opened openedTerminal
	json.Unmarshal(data, &opened)
	if !api.ValidTerminalSession(opened.Session) {
		t.Fatalf("session %q", opened.Session)
	}
	signed := sign.Signed{Envelope: []byte("e"), Signature: []byte("s")}
	if code, _ := e.do(admin, "POST", "/api/tasks/"+opened.ID+"/signature", signed); code != http.StatusNoContent {
		t.Fatalf("signature: %d", code)
	}
	if code, _ := e.do(agent, "GET", "/agent/tasks?wait=0", nil); code != http.StatusOK {
		t.Fatalf("poll: %d", code)
	}
	return id, agent, admin, opened
}

func (e *env) dial(c *http.Client, path string, header http.Header) (*websocket.Conn, *http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return websocket.Dial(ctx, e.ts.URL+path, &websocket.DialOptions{HTTPClient: c, HTTPHeader: header})
}

func readText(t *testing.T, conn *websocket.Conn) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	kind, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if kind != websocket.MessageText {
		t.Fatalf("got binary %q", data)
	}
	return string(data)
}

func TestTerminalRelaysBothWays(t *testing.T) {
	e := setup(t)
	_, agent, admin, opened := openTerminal(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	browser, _, err := e.dial(admin, "/api/terminal/"+opened.Session, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer browser.CloseNow()
	if got := readText(t, browser); got != `{"state":"waiting"}` {
		t.Fatalf("got %s", got)
	}
	device, _, err := e.dial(agent, "/agent/terminal/"+opened.Session, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer device.CloseNow()
	if got := readText(t, browser); got != `{"state":"open"}` {
		t.Fatalf("got %s", got)
	}

	if err := browser.Write(ctx, websocket.MessageBinary, []byte("id -u\n")); err != nil {
		t.Fatal(err)
	}
	kind, data, err := device.Read(ctx)
	if err != nil || kind != websocket.MessageBinary || string(data) != "id -u\n" {
		t.Fatalf("device got %v %q %v", kind, data, err)
	}
	if err := device.Write(ctx, websocket.MessageBinary, []byte("0\r\n")); err != nil {
		t.Fatal(err)
	}
	kind, data, err = browser.Read(ctx)
	if err != nil || kind != websocket.MessageBinary || string(data) != "0\r\n" {
		t.Fatalf("browser got %v %q %v", kind, data, err)
	}

	// A browser that connects again sees what came before.
	again, _, err := e.dial(admin, "/api/terminal/"+opened.Session, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer again.CloseNow()
	readText(t, again)
	readText(t, again)
	if _, data, err := again.Read(ctx); err != nil || string(data) != "0\r\n" {
		t.Fatalf("replay %q %v", data, err)
	}
	if _, _, err := browser.Read(ctx); websocket.CloseStatus(err) != websocket.StatusNormalClosure {
		t.Fatalf("the replaced browser stays: %v", err)
	}

	device.Close(websocket.StatusNormalClosure, "shell ended")
	_, _, err = again.Read(ctx)
	var ce websocket.CloseError
	if !errors.As(err, &ce) || ce.Reason != "shell ended" {
		t.Fatalf("browser end: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		audit, err := e.store.ListAudit(context.Background(), 50)
		if err != nil {
			t.Fatal(err)
		}
		var actions []string
		for _, entry := range audit {
			actions = append(actions, entry.Action+" "+entry.Actor+" "+entry.Detail)
		}
		joined := strings.Join(actions, "\n")
		if strings.Contains(joined, "terminal.started admin") && strings.Contains(joined, "terminal.ended admin") {
			if strings.Contains(joined, "id -u") {
				t.Fatal("the audit log holds what was typed")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit: %s", joined)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if e.server.terminals.get(opened.Session) != nil {
		t.Fatal("the session is still known")
	}
}

func TestTerminalRefusesStrangers(t *testing.T) {
	e := setup(t)
	_, _, _, opened := openTerminal(t, e)
	ctx := context.Background()
	hash, _ := HashPassword(testPassword)
	if _, err := e.store.CreateUser(ctx, "bob", "bob", hash, "admin"); err != nil {
		t.Fatal(err)
	}
	_, other := e.enroll()
	for name, c := range map[string]struct {
		client *http.Client
		path   string
		header http.Header
		status int
	}{
		"another admin":      {e.login("bob"), "/api/terminal/" + opened.Session, nil, http.StatusNotFound},
		"a member":           {e.login("anna"), "/api/terminal/" + opened.Session, nil, http.StatusForbidden},
		"another page":       {e.login("admin"), "/api/terminal/" + opened.Session, http.Header{"Origin": {"https://evil.example"}}, http.StatusForbidden},
		"another device":     {other, "/agent/terminal/" + opened.Session, nil, http.StatusNotFound},
		"an unknown session": {e.login("admin"), "/api/terminal/x", nil, http.StatusNotFound},
		"no certificate":     {e.client(), "/agent/terminal/" + opened.Session, nil, http.StatusUnauthorized},
	} {
		conn, resp, err := e.dial(c.client, c.path, c.header)
		if err == nil {
			conn.CloseNow()
			t.Errorf("%s: connected", name)
			continue
		}
		if resp == nil || resp.StatusCode != c.status {
			t.Errorf("%s: %v %v", name, resp, err)
		}
	}
}

func TestTerminalWaitsForTheApproval(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	protect(t, e, agent)
	admin := e.login("admin")
	code, data := e.do(admin, "POST", "/api/devices/"+id+"/terminal", map[string]any{"user": "root"})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, data)
	}
	var opened openedTerminal
	json.Unmarshal(data, &opened)
	// Not signed yet, so the device has not admitted it either.
	if _, resp, err := e.dial(agent, "/agent/terminal/"+opened.Session, nil); err == nil || resp.StatusCode != http.StatusConflict {
		t.Fatalf("connected before the approval: %v", err)
	}
}

func TestTerminalOnlyThroughItsRoute(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	admin := e.login("admin")
	if code, data := e.do(admin, "POST", "/api/devices/"+id+"/terminal", map[string]any{"user": "root"}); code != http.StatusConflict {
		t.Fatalf("unprotected: %d %s", code, data)
	}
	protect(t, e, agent)
	payload := api.TerminalPayload{Session: strings.Repeat("A", 43), User: "root", Minutes: 5}
	if code, data := e.do(admin, "POST", "/api/devices/"+id+"/tasks", map[string]any{"type": api.TaskTerminalOpen, "payload": payload}); code != http.StatusBadRequest {
		t.Fatalf("generic route: %d %s", code, data)
	}
	if code, data := e.do(admin, "POST", "/api/devices/"+id+"/terminal", map[string]any{"user": "x;y"}); code != http.StatusBadRequest {
		t.Fatalf("bad user: %d %s", code, data)
	}
	if code, data := e.do(admin, "POST", "/api/devices/"+id+"/terminal", map[string]any{"user": "root", "minutes": 500}); code != http.StatusBadRequest {
		t.Fatalf("too long: %d %s", code, data)
	}
}

func TestPasskeyApprovalOfATerminalIsShort(t *testing.T) {
	if got := envelopeLifetime(api.TaskTerminalOpen); got > api.MaxTerminalApproval || got < time.Minute {
		t.Fatalf("terminal approvals last %s", got)
	}
	if got := envelopeLifetime(api.TaskPkgInstall); got != passkeyEnvelopeLifetime {
		t.Fatalf("other approvals last %s", got)
	}
}

func TestPublicAddresses(t *testing.T) {
	for address, public := range map[string]bool{
		"127.0.0.1":       false,
		"192.168.1.10":    false,
		"10.0.0.1":        false,
		"172.16.5.4":      false,
		"100.100.1.1":     false, // shared address space, as Tailscale uses
		"169.254.1.1":     false,
		"fe80::1":         false,
		"fd00::1":         false,
		"::1":             false,
		"8.8.8.8":         true,
		"2a00:1450::1":    true,
		"::ffff:8.8.4.4":  true,
		"::ffff:10.0.0.1": false,
	} {
		if got := publicAddress(netip.MustParseAddr(address)); got != public {
			t.Errorf("%s: public %v", address, got)
		}
	}
}

func TestAttentionWarnsAboutRequestsFromOutside(t *testing.T) {
	e := setup(t)
	admin := e.login("admin")
	code, data := e.do(admin, "GET", "/api/attention", nil)
	if code != http.StatusOK || !strings.Contains(string(data), `"exposure":null`) {
		t.Fatalf("got %d %s", code, data)
	}
	e.server.seen(&http.Request{RemoteAddr: "203.0.113.7:4711"})
	_, data = e.do(admin, "GET", "/api/attention", nil)
	if !strings.Contains(string(data), `"reason":"reached"`) || !strings.Contains(string(data), `"address":"203.0.113.7"`) {
		t.Fatalf("got %s", data)
	}
	e.server.AllowPublic(true)
	_, data = e.do(admin, "GET", "/api/attention", nil)
	if !strings.Contains(string(data), `"exposure":null`) {
		t.Fatalf("allowed, still warns: %s", data)
	}
}

func TestListeningOnAPublicAddressWarns(t *testing.T) {
	e := setup(t)
	e.server.CheckListen("127.0.0.1:8443")
	if got := e.server.currentExposure(); got != nil {
		t.Fatalf("loopback warns: %+v", got)
	}
	e.server.CheckListen("198.51.100.4:8443")
	if got := e.server.currentExposure(); got == nil || got.Reason != "listening" || got.Address != "198.51.100.4" {
		t.Fatalf("got %+v", got)
	}
}

// A device that refuses the session says why, and the browser waiting for it
// hears that instead of waiting for minutes.
func TestTerminalEndsWhenTheDeviceRefuses(t *testing.T) {
	e := setup(t)
	_, agent, admin, opened := openTerminal(t, e)
	browser, _, err := e.dial(admin, "/api/terminal/"+opened.Session, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer browser.CloseNow()
	readText(t, browser)
	result := api.TaskResult{OK: false, Output: "no account nobody on this device"}
	if code, data := e.do(agent, "POST", "/agent/tasks/"+opened.ID+"/result", result); code != http.StatusNoContent {
		t.Fatalf("result: %d %s", code, data)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err = browser.Read(ctx)
	var ce websocket.CloseError
	if !errors.As(err, &ce) || ce.Reason != "no account nobody on this device" {
		t.Fatalf("got %v", err)
	}
	if e.server.terminals.get(opened.Session) != nil {
		t.Fatal("the session is still known")
	}
}

func TestCloseTextFitsAFrame(t *testing.T) {
	long := strings.Repeat("ä", 100) + "\nnext line"
	got := closeText(long)
	if len(got) > 123 || strings.Contains(got, "\n") || !utf8Valid(got) {
		t.Fatalf("got %d bytes: %q", len(got), got)
	}
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "�") == s }
