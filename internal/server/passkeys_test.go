package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/philippe/hauswart/internal/api"
	"github.com/philippe/hauswart/internal/sign"
	"github.com/philippe/hauswart/internal/sign/passkeytest"
	"github.com/philippe/hauswart/internal/store"
)

const testOrigin = "https://test"

// authenticator matches the public URL of the test server.
func authenticator(t *testing.T) *passkeytest.Authenticator {
	t.Helper()
	a := passkeytest.New(t)
	a.Origin, a.RPID = testOrigin, "test"
	return a
}

func (e *env) register(c *http.Client, a *passkeytest.Authenticator) {
	e.t.Helper()
	code, data := e.do(c, "POST", "/api/passkeys/options", nil)
	if code != http.StatusOK {
		e.t.Fatalf("options: %d %s", code, data)
	}
	var options struct {
		Challenge []byte `json:"challenge"`
		RPID      string `json:"rp_id"`
	}
	json.Unmarshal(data, &options)
	if options.RPID != "test" {
		e.t.Fatalf("relying party %q", options.RPID)
	}
	client, _ := json.Marshal(map[string]string{
		"type": "webauthn.create", "origin": testOrigin,
		"challenge": base64.RawURLEncoding.EncodeToString(options.Challenge),
	})
	code, data = e.do(c, "POST", "/api/passkeys", map[string]any{
		"name": "phone", "credential_id": a.CredentialID, "public_key": a.Pin(e.t).PublicKey, "client_data_json": client,
	})
	if code != http.StatusCreated {
		e.t.Fatalf("register: %d %s", code, data)
	}
}

// reportPins has the device report its pinned passkeys.
func (e *env) reportPins(agent *http.Client, counter uint64, list ...*passkeytest.Authenticator) {
	e.t.Helper()
	report := api.Report{Hostname: "laptop", Protected: true, PasskeyCounter: counter}
	for _, a := range list {
		report.Passkeys = append(report.Passkeys, base64.RawURLEncoding.EncodeToString(a.CredentialID))
	}
	if code, _ := e.do(agent, "POST", "/agent/report", report); code != http.StatusNoContent {
		e.t.Fatalf("report: %d", code)
	}
}

func (e *env) queue(device, taskType string, payload any) string {
	e.t.Helper()
	code, data := e.do(e.login("admin"), "POST", "/api/devices/"+device+"/tasks", map[string]any{"type": taskType, "payload": payload})
	if code != http.StatusCreated {
		e.t.Fatalf("task: %d %s", code, data)
	}
	var out struct{ ID string }
	json.Unmarshal(data, &out)
	return out.ID
}

type challenge struct {
	Envelope    []byte   `json:"envelope"`
	Credentials [][]byte `json:"credentials"`
	RPID        string   `json:"rp_id"`
}

func (e *env) challenge(c *http.Client, task string) challenge {
	e.t.Helper()
	code, data := e.do(c, "POST", "/api/tasks/"+task+"/passkey-challenge", nil)
	if code != http.StatusOK {
		e.t.Fatalf("challenge: %d %s", code, data)
	}
	var out challenge
	json.Unmarshal(data, &out)
	return out
}

var vim = api.PackagesPayload{Packages: []string{"vim"}}

type passkeyEnv struct {
	*env
	device string
	agent  *http.Client
	parent *http.Client
	key    *passkeytest.Authenticator
}

func setupPasskey(t *testing.T) passkeyEnv {
	t.Helper()
	e := setup(t)
	id, agent := e.enroll()
	e.addUser("mama", "mama", store.RoleParent)
	parent := e.login("mama")
	a := authenticator(t)
	e.register(parent, a)
	e.reportPins(agent, 0, a)
	return passkeyEnv{env: e, device: id, agent: agent, parent: parent, key: a}
}

func TestPasskeyApprovalReachesTheDevice(t *testing.T) {
	p := setupPasskey(t)
	task := p.queue(p.device, api.TaskPkgInstall, vim)

	_, data := p.do(p.parent, "GET", "/api/approvals", nil)
	if !strings.Contains(string(data), task) {
		t.Fatalf("not in the queue: %s", data)
	}
	c := p.challenge(p.parent, task)
	var env sign.Envelope
	if err := json.Unmarshal(c.Envelope, &env); err != nil {
		t.Fatal(err)
	}
	if env.Type != api.TaskPkgInstall || env.DeviceID != p.device || env.Counter != 1 {
		t.Fatalf("envelope %+v", env)
	}
	if code, data := p.do(p.parent, "POST", "/api/tasks/"+task+"/passkey-approval", p.key.Assert(t, c.Envelope)); code != http.StatusNoContent {
		t.Fatalf("approval: %d %s", code, data)
	}
	code, data := p.do(p.agent, "GET", "/agent/tasks?wait=0", nil)
	if code != http.StatusOK {
		t.Fatalf("poll: %d", code)
	}
	var delivered api.Task
	json.Unmarshal(data, &delivered)
	if delivered.Signed == nil || delivered.Signed.Passkey == nil {
		t.Fatalf("got %s", data)
	}
	if _, _, err := sign.VerifyPasskey(*delivered.Signed, []sign.Passkey{func() sign.Passkey {
		pin := p.key.Pin(t)
		pin.Origin, pin.RPID = testOrigin, "test"
		return pin
	}()}, env.NotAfter.Add(-1)); err != nil {
		t.Fatalf("what reaches the device does not verify: %v", err)
	}
}

func TestPasskeyChallengeIsStable(t *testing.T) {
	p := setupPasskey(t)
	task := p.queue(p.device, api.TaskPkgInstall, vim)
	first := p.challenge(p.parent, task)
	second := p.challenge(p.parent, task)
	if string(first.Envelope) != string(second.Envelope) {
		t.Fatal("repeating the request used up a counter")
	}
}

func TestPasskeyCounterStaysAboveWhatTheDeviceReports(t *testing.T) {
	p := setupPasskey(t)
	p.reportPins(p.agent, 41, p.key)
	var env sign.Envelope
	json.Unmarshal(p.challenge(p.parent, p.queue(p.device, api.TaskPkgInstall, vim)).Envelope, &env)
	if env.Counter != 42 {
		t.Fatalf("counter %d", env.Counter)
	}
	// A hacked device cannot overflow what the server stores.
	p.reportPins(p.agent, 1<<64-1, p.key)
	json.Unmarshal(p.challenge(p.parent, p.queue(p.device, api.TaskPkgInstall, vim)).Envelope, &env)
	if env.Counter == 0 || env.Counter == 1<<64-1 {
		t.Fatalf("counter %d", env.Counter)
	}
}

func TestPasskeyChallengeRefusesCLIOnlyTypes(t *testing.T) {
	p := setupPasskey(t)
	for _, taskType := range []string{api.TaskFilePut, api.TaskSudoGrant, api.TaskUserLock} {
		id, err := p.store.CreateSigningTask(context.Background(), p.device, taskType, []byte(`{"secret":"x"}`), "admin")
		if err != nil {
			t.Fatal(err)
		}
		code, data := p.do(p.parent, "POST", "/api/tasks/"+id+"/passkey-challenge", nil)
		if code != http.StatusConflict || strings.Contains(string(data), "secret") {
			t.Fatalf("%s: %d %s", taskType, code, data)
		}
		_, data = p.do(p.parent, "GET", "/api/approvals", nil)
		if strings.Contains(string(data), id) {
			t.Fatalf("%s reached the parent's queue", taskType)
		}
		if code, _ := p.do(p.parent, "POST", "/api/tasks/"+id+"/reject", nil); code != http.StatusForbidden {
			t.Fatalf("%s: parent rejected: %d", taskType, code)
		}
	}
}

func TestPasskeyApprovalRefusals(t *testing.T) {
	p := setupPasskey(t)
	task := p.queue(p.device, api.TaskPkgInstall, vim)
	c := p.challenge(p.parent, task)
	url := "/api/tasks/" + task + "/passkey-approval"

	foreign := authenticator(t)
	if code, _ := p.do(p.parent, "POST", url, foreign.Assert(t, c.Envelope)); code != http.StatusForbidden {
		t.Fatalf("foreign passkey: %d", code)
	}
	wrong := *p.key
	wrong.Origin = "https://evil.example"
	if code, _ := p.do(p.parent, "POST", url, wrong.Assert(t, c.Envelope)); code != http.StatusForbidden {
		t.Fatalf("wrong origin: %d", code)
	}
	if code, _ := p.do(p.parent, "POST", url, p.key.Assert(t, []byte("other envelope"))); code != http.StatusForbidden {
		t.Fatalf("other envelope: %d", code)
	}
	// Nothing of this may reach the device.
	if code, _ := p.do(p.agent, "GET", "/agent/tasks?wait=0", nil); code != http.StatusNoContent {
		t.Fatalf("delivered: %d", code)
	}
	// Approving needs one's own passkey, not somebody else's assertion.
	p.addUser("papa", "papa", store.RoleParent)
	if code, _ := p.do(p.login("papa"), "POST", url, p.key.Assert(t, c.Envelope)); code != http.StatusForbidden {
		t.Fatalf("assertion of another user: %d", code)
	}
	if code, _ := p.do(p.parent, "POST", url, p.key.Assert(t, c.Envelope)); code != http.StatusNoContent {
		t.Fatal("the real approval failed")
	}
	if code, _ := p.do(p.parent, "POST", url, p.key.Assert(t, c.Envelope)); code != http.StatusConflict {
		t.Fatalf("second approval: %d", code)
	}
}

func TestPasskeyNotPinnedOnDevice(t *testing.T) {
	p := setupPasskey(t)
	p.reportPins(p.agent, 0)
	task := p.queue(p.device, api.TaskPkgInstall, vim)
	if code, _ := p.do(p.parent, "POST", "/api/tasks/"+task+"/passkey-challenge", nil); code != http.StatusConflict {
		t.Fatalf("got %d", code)
	}
}

func TestPasskeyRoutesRefuseMembers(t *testing.T) {
	p := setupPasskey(t)
	member := p.login("anna")
	for _, r := range []struct{ method, path string }{
		{"GET", "/api/passkeys"},
		{"POST", "/api/passkeys/options"},
		{"POST", "/api/passkeys"},
		{"DELETE", "/api/passkeys/1"},
		{"GET", "/api/approvals"},
		{"POST", "/api/tasks/x/passkey-challenge"},
		{"POST", "/api/tasks/x/passkey-approval"},
	} {
		if code, _ := p.do(member, r.method, r.path, map[string]any{}); code != http.StatusForbidden {
			t.Errorf("%s %s: %d", r.method, r.path, code)
		}
	}
}

func TestPasskeysBelongToTheirOwner(t *testing.T) {
	p := setupPasskey(t)
	p.addUser("papa", "papa", store.RoleParent)
	papa := p.login("papa")
	_, data := p.do(papa, "GET", "/api/passkeys", nil)
	if strings.TrimSpace(string(data)) != "[]" {
		t.Fatalf("sees a foreign passkey: %s", data)
	}
	rows, err := p.store.ListPasskeys(context.Background(), 0)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%v %v", rows, err)
	}
	path := fmt.Sprintf("/api/passkeys/%d", rows[0].ID)
	if code, _ := p.do(papa, "DELETE", path, nil); code != http.StatusNotFound {
		t.Fatalf("deleted a foreign passkey: %d", code)
	}
	// The admin tool lists everything to pin from.
	_, data = p.do(p.login("admin"), "GET", "/api/passkeys", nil)
	if !strings.Contains(string(data), "phone") {
		t.Fatalf("got %s", data)
	}
	if code, _ := p.do(p.parent, "DELETE", path, nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
}

func TestPasskeyRegistrationRefusals(t *testing.T) {
	e := setup(t)
	e.addUser("mama", "mama", store.RoleParent)
	parent := e.login("mama")
	a := authenticator(t)
	public := a.Pin(t).PublicKey

	register := func(challenge []byte, origin, kind string) int {
		client, _ := json.Marshal(map[string]string{
			"type": kind, "origin": origin, "challenge": base64.RawURLEncoding.EncodeToString(challenge),
		})
		code, _ := e.do(parent, "POST", "/api/passkeys", map[string]any{
			"name": "phone", "credential_id": a.CredentialID, "public_key": public, "client_data_json": client,
		})
		return code
	}
	options := func() []byte {
		_, data := e.do(parent, "POST", "/api/passkeys/options", nil)
		var out struct {
			Challenge []byte `json:"challenge"`
		}
		json.Unmarshal(data, &out)
		return out.Challenge
	}
	if code := register([]byte("guess"), testOrigin, "webauthn.create"); code != http.StatusBadRequest {
		t.Fatalf("no open registration: %d", code)
	}
	if code := register(options(), "https://evil.example", "webauthn.create"); code != http.StatusBadRequest {
		t.Fatalf("wrong origin: %d", code)
	}
	if code := register(options(), testOrigin, "webauthn.get"); code != http.StatusBadRequest {
		t.Fatalf("wrong type: %d", code)
	}
	used := options()
	if code := register(used, testOrigin, "webauthn.create"); code != http.StatusCreated {
		t.Fatalf("valid: %d", code)
	}
	if code := register(used, testOrigin, "webauthn.create"); code != http.StatusBadRequest {
		t.Fatalf("challenge used twice: %d", code)
	}
}

func TestPasskeysNeedADNSName(t *testing.T) {
	for url, want := range map[string]bool{
		"https://hauswart.home.arpa:8443": true,
		"https://10.8.0.1:8443":           false,
		"https://[fd00::1]:8443":          false,
		"http://hauswart.home.arpa:8443":  false,
	} {
		s := &Server{publicURL: url}
		if _, _, ok := s.relyingParty(); ok != want {
			t.Errorf("%s: %v", url, ok)
		}
	}
}

// Approving in a different order than the counters must either work or ask for
// a new approval, and never send the device a task it has to refuse.
func TestPasskeyTasksReachTheDeviceInCounterOrder(t *testing.T) {
	p := setupPasskey(t)
	first := p.queue(p.device, api.TaskPkgInstall, vim)
	second := p.queue(p.device, api.TaskPkgInstall, api.PackagesPayload{Packages: []string{"git"}})
	c2 := p.challenge(p.parent, second)
	c1 := p.challenge(p.parent, first)
	for _, approval := range []struct {
		task string
		c    challenge
	}{{first, c1}, {second, c2}} {
		if code, _ := p.do(p.parent, "POST", "/api/tasks/"+approval.task+"/passkey-approval", p.key.Assert(t, approval.c.Envelope)); code != http.StatusNoContent {
			t.Fatalf("approval: %d", code)
		}
	}
	var last uint64
	for range 2 {
		code, data := p.do(p.agent, "GET", "/agent/tasks?wait=0", nil)
		if code != http.StatusOK {
			t.Fatalf("poll: %d", code)
		}
		var task api.Task
		json.Unmarshal(data, &task)
		var env sign.Envelope
		json.Unmarshal(task.Signed.Envelope, &env)
		if env.Counter <= last {
			t.Fatalf("counter %d after %d", env.Counter, last)
		}
		last = env.Counter
	}
}

func TestOvertakenPasskeyApprovalAsksAgain(t *testing.T) {
	p := setupPasskey(t)
	early := p.queue(p.device, api.TaskPkgInstall, vim)
	late := p.queue(p.device, api.TaskPkgInstall, api.PackagesPayload{Packages: []string{"git"}})
	stale := p.challenge(p.parent, early)
	c := p.challenge(p.parent, late)
	if code, _ := p.do(p.parent, "POST", "/api/tasks/"+late+"/passkey-approval", p.key.Assert(t, c.Envelope)); code != http.StatusNoContent {
		t.Fatalf("approval: %d", code)
	}
	if code, _ := p.do(p.agent, "GET", "/agent/tasks?wait=0", nil); code != http.StatusOK {
		t.Fatalf("poll: %d", code)
	}
	if code, _ := p.do(p.parent, "POST", "/api/tasks/"+early+"/passkey-approval", p.key.Assert(t, stale.Envelope)); code != http.StatusConflict {
		t.Fatalf("stale approval: %d", code)
	}
	fresh := p.challenge(p.parent, early)
	if string(fresh.Envelope) == string(stale.Envelope) {
		t.Fatal("kept the stale envelope")
	}
	if code, _ := p.do(p.parent, "POST", "/api/tasks/"+early+"/passkey-approval", p.key.Assert(t, fresh.Envelope)); code != http.StatusNoContent {
		t.Fatalf("second try: %d", code)
	}
}

// The signing tool still works for a task someone looked at with a passkey.
func TestSignatureWinsOverPreparedEnvelope(t *testing.T) {
	p := setupPasskey(t)
	task := p.queue(p.device, api.TaskPkgInstall, vim)
	c := p.challenge(p.parent, task)
	admin := p.login("admin")
	signed := sign.Signed{Envelope: []byte("e"), Signature: []byte("s")}
	if code, _ := p.do(admin, "POST", "/api/tasks/"+task+"/signature", signed); code != http.StatusNoContent {
		t.Fatalf("signature: %d", code)
	}
	if code, _ := p.do(p.parent, "POST", "/api/tasks/"+task+"/passkey-approval", p.key.Assert(t, c.Envelope)); code != http.StatusConflict {
		t.Fatalf("approval after the signature: %d", code)
	}
}
