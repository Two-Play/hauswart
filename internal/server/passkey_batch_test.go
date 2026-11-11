package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/sign"
)

type batchChallenge struct {
	Items []batchItem `json:"items"`
}

func (p passkeyEnv) batchChallenge(tasks ...string) (int, batchChallenge, []byte) {
	code, data := p.do(p.parent, "POST", "/api/passkey-batch/challenge", map[string]any{"tasks": tasks})
	var out batchChallenge
	json.Unmarshal(data, &out)
	return code, out, data
}

// One touch approves two tasks on one device. Both reach it, in counter order,
// and each verifies there on its own.
func TestBatchApprovalReachesTheDevice(t *testing.T) {
	p := setupPasskey(t)
	one := p.queue(p.device, api.TaskPkgInstall, vim)
	two := p.queue(p.device, api.TaskPkgInstall, api.PackagesPayload{Packages: []string{"htop"}})
	code, c, data := p.batchChallenge(one, two)
	if code != http.StatusOK || len(c.Items) != 2 {
		t.Fatalf("challenge: %d %s", code, data)
	}
	hashes := [][]byte{sign.EnvelopeHash(c.Items[0].Envelope), sign.EnvelopeHash(c.Items[1].Envelope)}
	assertion := p.key.AssertChallenge(t, sign.PasskeyBatchChallenge(hashes))
	code, data = p.do(p.parent, "POST", "/api/passkey-batch/approval", map[string]any{"tasks": []string{one, two}, "assertion": assertion})
	var results []batchResult
	if code != http.StatusOK || json.Unmarshal(data, &results) != nil || len(results) != 2 || !results[0].OK || !results[1].OK {
		t.Fatalf("approval: %d %s", code, data)
	}
	pin := p.key.Pin(t)
	pin.Origin, pin.RPID = testOrigin, "test"
	var last uint64
	for range 2 {
		_, data := p.do(p.agent, "GET", "/agent/tasks?wait=0", nil)
		var delivered api.Task
		json.Unmarshal(data, &delivered)
		if delivered.Signed == nil || len(delivered.Signed.Batch) != 2 {
			t.Fatalf("got %s", data)
		}
		env, _, err := sign.VerifyPasskey(*delivered.Signed, []sign.Passkey{pin}, env0(t, c).NotAfter.Add(-1))
		if err != nil {
			t.Fatalf("what reaches the device does not verify: %v", err)
		}
		if env.Counter <= last {
			t.Fatalf("counter %d after %d", env.Counter, last)
		}
		last = env.Counter
		p.do(p.agent, "POST", "/agent/tasks/"+delivered.ID+"/result", api.TaskResult{OK: true})
	}
}

func env0(t *testing.T, c batchChallenge) sign.Envelope {
	t.Helper()
	var env sign.Envelope
	if err := json.Unmarshal(c.Items[0].Envelope, &env); err != nil {
		t.Fatal(err)
	}
	return env
}

// An assertion over another list approves nothing.
func TestBatchApprovalRefusesAnotherList(t *testing.T) {
	p := setupPasskey(t)
	one := p.queue(p.device, api.TaskPkgInstall, vim)
	two := p.queue(p.device, api.TaskPkgRemove, vim)
	_, c, _ := p.batchChallenge(one, two)
	wrong := p.key.AssertChallenge(t, sign.PasskeyBatchChallenge([][]byte{sign.EnvelopeHash(c.Items[0].Envelope), make([]byte, 32)}))
	_, data := p.do(p.parent, "POST", "/api/passkey-batch/approval", map[string]any{"tasks": []string{one, two}, "assertion": wrong})
	var results []batchResult
	json.Unmarshal(data, &results)
	if len(results) != 2 || results[0].OK || results[1].OK {
		t.Fatalf("%s", data)
	}
	_, waiting := p.do(p.parent, "GET", "/api/approvals", nil)
	var list []struct{ ID string }
	if json.Unmarshal(waiting, &list) != nil || len(list) != 2 {
		t.Fatalf("no longer waiting: %s", waiting)
	}
}

func TestBatchSize(t *testing.T) {
	p := setupPasskey(t)
	one := p.queue(p.device, api.TaskPkgInstall, vim)
	for name, tasks := range map[string][]string{"one": {one}, "twice": {one, one}} {
		if code, _, data := p.batchChallenge(tasks...); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, code, data)
		}
	}
}
