package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/philippe/hauswart/internal/api"
	"github.com/philippe/hauswart/internal/sign"
)

const guardDevice = "this-device"

func newKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func newGuard(t *testing.T, signer ssh.Signer) *Guard {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guard.json")
	if err := CreateGuard(path); err != nil {
		t.Fatal(err)
	}
	g, err := OpenGuard(path, []string{sign.FormatKey(signer.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func signedTask(t *testing.T, signer ssh.Signer, device string, counter uint64, notAfter time.Time) api.Task {
	t.Helper()
	s, err := sign.Sign(signer, sign.Envelope{
		Type:     api.TaskPkgInstall,
		Payload:  json.RawMessage(`{"packages":["vim"]}`),
		DeviceID: device,
		Counter:  counter,
		NotAfter: notAfter,
	})
	if err != nil {
		t.Fatal(err)
	}
	return api.Task{ID: "id", Type: api.TaskPkgInstall, Signed: &s}
}

func TestGuardAdmitsSignedTask(t *testing.T) {
	signer := newKey(t)
	g := newGuard(t, signer)
	task, err := g.Admit(signedTask(t, signer, guardDevice, 1, time.Now().Add(time.Hour)), guardDevice, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if task.Type != api.TaskPkgInstall || string(task.Payload) != `{"packages":["vim"]}` {
		t.Fatalf("got %+v", task)
	}
}

// The server controls the outer fields, so they must not survive.
func TestGuardUsesOnlySignedFields(t *testing.T) {
	signer := newKey(t)
	g := newGuard(t, signer)
	task := signedTask(t, signer, guardDevice, 1, time.Now().Add(time.Hour))
	task.Type = api.TaskSudoGrant
	task.Payload = json.RawMessage(`{"user":"evil"}`)
	admitted, err := g.Admit(task, guardDevice, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if admitted.Type != api.TaskPkgInstall || string(admitted.Payload) == `{"user":"evil"}` {
		t.Fatalf("server fields survived: %+v", admitted)
	}
}

func TestGuardRejects(t *testing.T) {
	signer := newKey(t)
	soon := time.Now().Add(time.Hour)
	cases := map[string]api.Task{
		"unsigned install":  {Type: api.TaskPkgInstall, Payload: json.RawMessage(`{"packages":["vim"]}`)},
		"unsigned sudo":     {Type: api.TaskSudoGrant, Payload: json.RawMessage(`{"user":"anna"}`)},
		"unsigned password": {Type: api.TaskUserPassword},
		"unsigned ca":       {Type: api.TaskCAInstall},
		"unsigned keys":     {Type: api.TaskKeysSet},
		"other device":      signedTask(t, signer, "other-device", 1, soon),
		"expired":           signedTask(t, signer, guardDevice, 1, time.Now().Add(-time.Second)),
		"zero counter":      signedTask(t, signer, guardDevice, 0, soon),
		"foreign key":       signedTask(t, newKey(t), guardDevice, 1, soon),
	}
	for name, task := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := newGuard(t, signer).Admit(task, guardDevice, time.Now()); err == nil {
				t.Fatal("admitted")
			}
		})
	}
}

func TestGuardAllowsSafeUnsignedTypes(t *testing.T) {
	g := newGuard(t, newKey(t))
	for _, taskType := range []string{api.TaskSudoRevoke, api.TaskPkgUpgrade} {
		if _, err := g.Admit(api.Task{Type: taskType}, guardDevice, time.Now()); err != nil {
			t.Errorf("%s: %v", taskType, err)
		}
	}
}

func TestGuardRejectsReplayAndReorder(t *testing.T) {
	signer := newKey(t)
	g := newGuard(t, signer)
	soon := time.Now().Add(time.Hour)
	first := signedTask(t, signer, guardDevice, 1, soon)
	second := signedTask(t, signer, guardDevice, 5, soon)
	if _, err := g.Admit(first, guardDevice, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Admit(first, guardDevice, time.Now()); err == nil {
		t.Fatal("replay admitted")
	}
	if _, err := g.Admit(second, guardDevice, time.Now()); err != nil {
		t.Fatal(err)
	}
	withheld := signedTask(t, signer, guardDevice, 3, soon)
	if _, err := g.Admit(withheld, guardDevice, time.Now()); err == nil {
		t.Fatal("task below the high-water mark admitted")
	}
}

func TestGuardCounterSurvivesRestart(t *testing.T) {
	signer := newKey(t)
	g := newGuard(t, signer)
	task := signedTask(t, signer, guardDevice, 7, time.Now().Add(time.Hour))
	if _, err := g.Admit(task, guardDevice, time.Now()); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenGuard(g.path, []string{sign.FormatKey(signer.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Admit(task, guardDevice, time.Now()); err == nil {
		t.Fatal("replay admitted after a restart")
	}
}

func TestGuardRefusesLostState(t *testing.T) {
	signer := newKey(t)
	g := newGuard(t, signer)
	if err := os.Remove(g.path); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenGuard(g.path, []string{sign.FormatKey(signer.PublicKey())}); err == nil {
		t.Fatal("lost state treated as a fresh start")
	}
}

func TestGuardRefusesClockRollback(t *testing.T) {
	signer := newKey(t)
	g := newGuard(t, signer)
	now := time.Now()
	if err := g.Touch(now); err != nil {
		t.Fatal(err)
	}
	expired := signedTask(t, signer, guardDevice, 1, now.Add(-time.Hour))
	if _, err := g.Admit(expired, guardDevice, now.Add(-2*time.Hour)); err == nil {
		t.Fatal("rolled back clock revived an expired task")
	}
	// Small corrections from time synchronisation are normal.
	task := signedTask(t, signer, guardDevice, 2, now.Add(time.Hour))
	if _, err := g.Admit(task, guardDevice, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestGuardRejectsWithoutKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard.json")
	if err := CreateGuard(path); err != nil {
		t.Fatal(err)
	}
	g, err := OpenGuard(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	task := signedTask(t, newKey(t), guardDevice, 1, time.Now().Add(time.Hour))
	if _, err := g.Admit(task, guardDevice, time.Now()); err == nil {
		t.Fatal("admitted without pinned keys")
	}
}
