package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/sign"
	"github.com/Two-Play/hauswart/internal/sign/passkeytest"
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

const passkeyPayload = `{"packages":["vim"]}`

func passkeyGuard(t *testing.T, a *passkeytest.Authenticator) *Guard {
	t.Helper()
	g := newGuard(t, newKey(t))
	// Long enough for the tests that move far into the future.
	pin := a.Pin(t)
	pin.NotAfter = time.Now().Add(365 * 24 * time.Hour)
	g.SetPasskeys([]sign.Passkey{pin}, api.DefaultPasskeyTypes)
	g.state.Freshness = testFreshness
	g.state.FreshnessAt = time.Now()
	return g
}

const testFreshness = "test-freshness"

// A hacked dashboard collects an approval now, for delivery months later.
func TestGuardRefusesStockpiledApprovals(t *testing.T) {
	a := passkeytest.New(t)
	g := passkeyGuard(t, a)
	now := time.Now()

	// It can pick any expiry, but it cannot know a value from the future.
	future := passkeyEnvelope(1)
	future.Freshness = "guessed"
	if _, err := g.Admit(approved(t, a, future), guardDevice, now); err == nil {
		t.Fatal("admitted an approval with an unknown freshness value")
	}
	empty := passkeyEnvelope(1)
	empty.Freshness = ""
	if _, err := g.Admit(approved(t, a, empty), guardDevice, now); err == nil {
		t.Fatal("admitted an approval without a freshness value")
	}

	collected := passkeyEnvelope(1)
	collected.NotAfter = now.Add(170 * 24 * time.Hour)
	task := approved(t, a, collected)
	late := now.Add(169*24*time.Hour + 12*time.Hour)
	_, err := g.Admit(task, guardDevice, late)
	if err == nil || !strings.Contains(err.Error(), "too old") {
		t.Fatalf("approval collected months ago: %v", err)
	}
}

func TestFreshnessKeepsApprovalsForADay(t *testing.T) {
	a := passkeytest.New(t)
	g := passkeyGuard(t, a)
	now := time.Now()

	// Rotated once: the value from before still counts.
	later := now.Add(passkeyFreshness + time.Minute)
	current, err := g.Freshness(later)
	if err != nil {
		t.Fatal(err)
	}
	if current == testFreshness {
		t.Fatal("value not rotated")
	}
	lasting := passkeyEnvelope(1)
	lasting.NotAfter = later.Add(time.Hour)
	if _, err := g.Admit(approved(t, a, lasting), guardDevice, later); err != nil {
		t.Fatalf("previous value refused: %v", err)
	}
	// Rotated twice: it is gone.
	muchLater := later.Add(passkeyFreshness + time.Minute)
	if _, err := g.Freshness(muchLater); err != nil {
		t.Fatal(err)
	}
	stale := passkeyEnvelope(2)
	stale.NotAfter = muchLater.Add(time.Hour)
	_, err = g.Admit(approved(t, a, stale), guardDevice, muchLater)
	if err == nil || !strings.Contains(err.Error(), "too old") {
		t.Fatalf("value older than a day: %v", err)
	}
}

// A device that was off for days must not accept what was collected before.
func TestFreshnessExpiresWhileSwitchedOff(t *testing.T) {
	a := passkeytest.New(t)
	g := passkeyGuard(t, a)
	back := time.Now().Add(5 * 24 * time.Hour)
	env := passkeyEnvelope(1)
	env.NotAfter = back.Add(time.Hour)
	_, err := g.Admit(approved(t, a, env), guardDevice, back)
	if err == nil || !strings.Contains(err.Error(), "too old") {
		t.Fatalf("old approval right after a long time off: %v", err)
	}
}

func TestPasskeyLimitIsASlidingWindow(t *testing.T) {
	a := passkeytest.New(t)
	g := passkeyGuard(t, a)
	start := time.Now()
	end := start.Add(passkeyTaskWindow - time.Minute)
	g.state.FreshnessAt = end
	at := func(counter uint64) sign.Envelope {
		env := passkeyEnvelope(counter)
		env.NotAfter = end.Add(time.Hour)
		return env
	}
	for i := range maxPasskeyTasks {
		if _, err := g.Admit(approved(t, a, at(uint64(i+1))), guardDevice, end); err != nil {
			t.Fatal(err)
		}
	}
	// With a fixed window, a new one would start here and allow 20 more.
	next := end.Add(2 * time.Minute)
	_, err := g.Admit(approved(t, a, at(maxPasskeyTasks+1)), guardDevice, next)
	if err == nil || !strings.Contains(err.Error(), "within a day") {
		t.Fatalf("limit at a window boundary: %v", err)
	}
}

func approved(t *testing.T, a *passkeytest.Authenticator, env sign.Envelope) api.Task {
	t.Helper()
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return api.Task{ID: "id", Type: env.Type, Signed: &sign.Signed{Envelope: raw, Passkey: a.Assert(t, raw)}}
}

func passkeyEnvelope(counter uint64) sign.Envelope {
	return sign.Envelope{
		Type:      api.TaskPkgInstall,
		Payload:   json.RawMessage(passkeyPayload),
		DeviceID:  guardDevice,
		Counter:   counter,
		NotAfter:  time.Now().Add(time.Hour),
		Freshness: testFreshness,
	}
}

func TestGuardAdmitsPasskeyTask(t *testing.T) {
	a := passkeytest.New(t)
	task := approved(t, a, passkeyEnvelope(1))
	// Nothing the server put next to the envelope survives.
	task.Type = api.TaskSudoGrant
	task.Payload = json.RawMessage(`{"user":"evil"}`)
	got, err := passkeyGuard(t, a).Admit(task, guardDevice, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != api.TaskPkgInstall || string(got.Payload) != passkeyPayload || got.Approver != "phone" {
		t.Fatalf("got %+v", got)
	}
}

// An approver has to be able to give more time from a phone.
func TestGuardAdmitsPasskeyExtension(t *testing.T) {
	a := passkeytest.New(t)
	env := passkeyEnvelope(1)
	env.Type = api.TaskScreenExtend
	got, err := passkeyGuard(t, a).Admit(approved(t, a, env), guardDevice, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != api.TaskScreenExtend {
		t.Fatalf("got %+v", got)
	}
}

func TestGuardRejectsPasskeyTasks(t *testing.T) {
	envelopeWith := func(change func(*sign.Envelope)) sign.Envelope {
		env := passkeyEnvelope(1)
		change(&env)
		return env
	}
	cases := map[string]sign.Envelope{
		"other device":   envelopeWith(func(e *sign.Envelope) { e.DeviceID = "other-device" }),
		"expired":        envelopeWith(func(e *sign.Envelope) { e.NotAfter = time.Now().Add(-time.Second) }),
		"far expiry":     envelopeWith(func(e *sign.Envelope) { e.NotAfter = time.Now().Add(25 * time.Hour) }),
		"zero counter":   envelopeWith(func(e *sign.Envelope) { e.Counter = 0 }),
		"huge counter":   envelopeWith(func(e *sign.Envelope) { e.Counter = 1<<64 - 1 }),
		"sudo":           envelopeWith(func(e *sign.Envelope) { e.Type = api.TaskSudoGrant }),
		"keys":           envelopeWith(func(e *sign.Envelope) { e.Type = api.TaskKeysSet }),
		"ca":             envelopeWith(func(e *sign.Envelope) { e.Type = api.TaskCAInstall }),
		"password":       envelopeWith(func(e *sign.Envelope) { e.Type = api.TaskUserPassword }),
		"file":           envelopeWith(func(e *sign.Envelope) { e.Type = api.TaskFilePut }),
		"user":           envelopeWith(func(e *sign.Envelope) { e.Type = api.TaskUserCreate }),
		"limit":          envelopeWith(func(e *sign.Envelope) { e.Type = api.TaskLimitSet }),
		"unknown future": envelopeWith(func(e *sign.Envelope) { e.Type = "some.future" }),
		"policy":         envelopeWith(func(e *sign.Envelope) { e.Type = api.TaskPolicySet }),
		"policy removal": envelopeWith(func(e *sign.Envelope) { e.Type = api.TaskPolicyClear }),
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			a := passkeytest.New(t)
			if _, err := passkeyGuard(t, a).Admit(approved(t, a, env), guardDevice, time.Now()); err == nil {
				t.Fatal("admitted")
			}
		})
	}
}

func TestGuardRejectsPasskeyThatIsNotPinned(t *testing.T) {
	a := passkeytest.New(t)
	task := approved(t, passkeytest.New(t), passkeyEnvelope(1))
	if _, err := passkeyGuard(t, a).Admit(task, guardDevice, time.Now()); err == nil {
		t.Fatal("admitted")
	}
}

func TestGuardRejectsPasskeyWrongOrigin(t *testing.T) {
	a := passkeytest.New(t)
	g := passkeyGuard(t, a)
	a.Origin = "https://evil.example"
	if _, err := g.Admit(approved(t, a, passkeyEnvelope(1)), guardDevice, time.Now()); err == nil {
		t.Fatal("admitted")
	}
}

func TestGuardRejectsPasskeyChangedEnvelope(t *testing.T) {
	a := passkeytest.New(t)
	task := approved(t, a, passkeyEnvelope(1))
	changed := passkeyEnvelope(1)
	changed.Payload = json.RawMessage(`{"packages":["nmap"]}`)
	raw, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	task.Signed.Envelope = raw
	if _, err := passkeyGuard(t, a).Admit(task, guardDevice, time.Now()); err == nil {
		t.Fatal("admitted")
	}
}

func TestGuardRejectsPasskeyReplay(t *testing.T) {
	a := passkeytest.New(t)
	g := passkeyGuard(t, a)
	task := approved(t, a, passkeyEnvelope(3))
	if _, err := g.Admit(task, guardDevice, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Admit(task, guardDevice, time.Now()); err == nil {
		t.Fatal("replay admitted")
	}
	if _, err := g.Admit(approved(t, a, passkeyEnvelope(2)), guardDevice, time.Now()); err == nil {
		t.Fatal("task below the high-water mark admitted")
	}
}

// Touch runs with every report. If it forgot the passkey counter, the server
// could replay any approval that has not expired yet.
func TestGuardPasskeyCounterSurvivesTouchSignedTaskAndRestart(t *testing.T) {
	a := passkeytest.New(t)
	signer := newKey(t)
	g := newGuard(t, signer)
	g.SetPasskeys([]sign.Passkey{a.Pin(t)}, api.DefaultPasskeyTypes)
	g.state.Freshness, g.state.FreshnessAt = testFreshness, time.Now()
	task := approved(t, a, passkeyEnvelope(3))
	if _, err := g.Admit(task, guardDevice, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := g.Touch(time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Admit(task, guardDevice, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("replay admitted after a report")
	}
	if _, err := g.Admit(signedTask(t, signer, guardDevice, 1, time.Now().Add(time.Hour)), guardDevice, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Admit(task, guardDevice, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("replay admitted after a signed task")
	}
	reopened, err := OpenGuard(g.path, []string{sign.FormatKey(signer.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	reopened.SetPasskeys([]sign.Passkey{a.Pin(t)}, api.DefaultPasskeyTypes)
	if _, err := reopened.Admit(task, guardDevice, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("replay admitted after a restart")
	}
}

// The two counters must not touch each other: an approval with a huge counter
// may not stop signed tasks, and signed tasks may not revive old approvals.
func TestGuardKeepsCountersApart(t *testing.T) {
	a := passkeytest.New(t)
	signer := newKey(t)
	g := newGuard(t, signer)
	g.SetPasskeys([]sign.Passkey{a.Pin(t)}, api.DefaultPasskeyTypes)
	g.state.Freshness, g.state.FreshnessAt = testFreshness, time.Now()
	if _, err := g.Admit(approved(t, a, passkeyEnvelope(1000)), guardDevice, time.Now()); err != nil {
		t.Fatal(err)
	}
	if g.Counter() != 0 {
		t.Fatalf("signing counter moved to %d", g.Counter())
	}
	if _, err := g.Admit(signedTask(t, signer, guardDevice, 1, time.Now().Add(time.Hour)), guardDevice, time.Now()); err != nil {
		t.Fatal(err)
	}
	if g.PasskeyCounter() != 1000 {
		t.Fatalf("passkey counter is %d", g.PasskeyCounter())
	}
}

func TestGuardLocalListNarrowsButNeverWidens(t *testing.T) {
	a := passkeytest.New(t)
	g := newGuard(t, newKey(t))
	g.SetPasskeys([]sign.Passkey{a.Pin(t)}, []string{api.TaskFlatpakInstall, api.TaskSudoGrant, api.TaskKeysSet})
	g.state.Freshness, g.state.FreshnessAt = testFreshness, time.Now()

	refused := passkeyEnvelope(1) // pkg.install, a default that this list leaves out
	if _, err := g.Admit(approved(t, a, refused), guardDevice, time.Now()); err == nil {
		t.Fatal("unlisted type admitted")
	}
	sudo := passkeyEnvelope(2)
	sudo.Type = api.TaskSudoGrant
	if _, err := g.Admit(approved(t, a, sudo), guardDevice, time.Now()); err == nil {
		t.Fatal("list widened beyond the ceiling")
	}
	allowed := passkeyEnvelope(3)
	allowed.Type = api.TaskFlatpakInstall
	if _, err := g.Admit(approved(t, a, allowed), guardDevice, time.Now()); err != nil {
		t.Fatal(err)
	}

	g.SetPasskeys([]sign.Passkey{a.Pin(t)}, []string{})
	allowed.Counter = 4
	if _, err := g.Admit(approved(t, a, allowed), guardDevice, time.Now()); err == nil {
		t.Fatal("empty list admitted a task")
	}
}

func TestGuardLimitsPasskeyTasksPerDay(t *testing.T) {
	a := passkeytest.New(t)
	g := passkeyGuard(t, a)
	now := time.Now()
	pin := a.Pin(t)
	pin.NotAfter = now.Add(2 * passkeyTaskWindow)
	g.SetPasskeys([]sign.Passkey{pin}, api.DefaultPasskeyTypes)
	for i := range maxPasskeyTasks {
		if _, err := g.Admit(approved(t, a, passkeyEnvelope(uint64(i+1))), guardDevice, now); err != nil {
			t.Fatal(err)
		}
	}
	over := passkeyEnvelope(maxPasskeyTasks + 1)
	if _, err := g.Admit(approved(t, a, over), guardDevice, now); err == nil {
		t.Fatal("limit ignored")
	}
	later := now.Add(passkeyTaskWindow)
	over.NotAfter = later.Add(time.Hour)
	fresh, err := g.Freshness(later)
	if err != nil {
		t.Fatal(err)
	}
	over.Freshness = fresh
	if _, err := g.Admit(approved(t, a, over), guardDevice, later); err != nil {
		t.Fatal(err)
	}
}

// The signing path is the way to recover, so a refused approval must not use up
// the limit or the counter.
func TestGuardRefusedPasskeyTaskChangesNothing(t *testing.T) {
	a := passkeytest.New(t)
	g := passkeyGuard(t, a)
	sudo := passkeyEnvelope(5)
	sudo.Type = api.TaskSudoGrant
	if _, err := g.Admit(approved(t, a, sudo), guardDevice, time.Now()); err == nil {
		t.Fatal("admitted")
	}
	if g.PasskeyCounter() != 0 {
		t.Fatalf("counter moved to %d", g.PasskeyCounter())
	}
}

func TestSignedKeysStayWithSignatures(t *testing.T) {
	signer := newKey(t)
	g := newGuard(t, signer)
	unsigned := api.Task{Type: api.TaskKeysSet, Payload: json.RawMessage(`{"keys":["x"]}`)}
	if _, err := g.Admit(unsigned, guardDevice, time.Now()); err == nil {
		t.Fatal("keys.set without a signature admitted")
	}
}

func testAgent(t *testing.T, cfg Config) *Agent {
	t.Helper()
	dir := t.TempDir()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, configFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, guardFile)
	if err := CreateGuard(path); err != nil {
		t.Fatal(err)
	}
	g, err := OpenGuard(path, cfg.SigningKeys)
	if err != nil {
		t.Fatal(err)
	}
	return &Agent{cfg: cfg, dir: dir, guard: g, log: slog.New(slog.DiscardHandler)}
}

func keysTask(t *testing.T, keys []string, passkeys []sign.Passkey) api.Task {
	t.Helper()
	raw, err := json.Marshal(api.KeysPayload{Keys: keys, Passkeys: passkeys})
	if err != nil {
		t.Fatal(err)
	}
	return api.Task{Type: api.TaskKeysSet, Payload: raw}
}

func readConfig(t *testing.T, dir string) Config {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestSetKeysPinsPasskeysAndKeepsTheLocalList(t *testing.T) {
	key := sign.FormatKey(newKey(t).PublicKey())
	a := testAgent(t, Config{DeviceID: guardDevice, SigningKeys: []string{key}, PasskeyTypes: []string{}})
	authenticator := passkeytest.New(t)

	if result := a.setKeys(keysTask(t, []string{key}, []sign.Passkey{authenticator.Pin(t)})); !result.OK {
		t.Fatal(result.Output)
	}
	cfg := readConfig(t, a.dir)
	if len(cfg.Passkeys) != 1 {
		t.Fatalf("passkeys: %+v", cfg.Passkeys)
	}
	// An empty list means no approvals. Turning it into null would mean the
	// default list, and so widen it.
	if cfg.PasskeyTypes == nil || len(cfg.PasskeyTypes) != 0 {
		t.Fatalf("local list changed: %#v", cfg.PasskeyTypes)
	}
	if _, types := a.guard.Passkeys(); len(types) != 0 {
		t.Fatalf("guard types: %v", types)
	}

	// Without passkeys in the task, the pin is gone, on disk and in memory.
	if result := a.setKeys(keysTask(t, []string{key}, nil)); !result.OK {
		t.Fatal(result.Output)
	}
	if cfg := readConfig(t, a.dir); len(cfg.Passkeys) != 0 {
		t.Fatalf("passkey survived: %+v", cfg.Passkeys)
	}
	if ids, _ := a.guard.Passkeys(); len(ids) != 0 {
		t.Fatalf("passkey survived in memory: %v", ids)
	}
}

// The owner may narrow the list while the agent runs, and a keys.set must not
// write the older copy from memory over that.
func TestSetKeysKeepsLocalEdits(t *testing.T) {
	key := sign.FormatKey(newKey(t).PublicKey())
	a := testAgent(t, Config{DeviceID: guardDevice, SigningKeys: []string{key}})
	edited := readConfig(t, a.dir)
	edited.PasskeyTypes = []string{api.TaskPkgUpgrade}
	raw, err := json.Marshal(edited)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.dir, configFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if result := a.setKeys(keysTask(t, []string{key}, nil)); !result.OK {
		t.Fatal(result.Output)
	}
	if got := readConfig(t, a.dir).PasskeyTypes; len(got) != 1 || got[0] != api.TaskPkgUpgrade {
		t.Fatalf("local edit lost: %v", got)
	}
}

func TestSetKeysRefusesInvalidPasskey(t *testing.T) {
	key := sign.FormatKey(newKey(t).PublicKey())
	a := testAgent(t, Config{DeviceID: guardDevice, SigningKeys: []string{key}})
	pin := passkeytest.New(t).Pin(t)
	pin.Origin = "https://10.8.0.1:8443"
	if result := a.setKeys(keysTask(t, []string{key}, []sign.Passkey{pin})); result.OK {
		t.Fatal("pinned an invalid passkey")
	}
	if got := readConfig(t, a.dir).Passkeys; len(got) != 0 {
		t.Fatalf("written: %+v", got)
	}
}

// A bad entry must cost that passkey only, never the agent.
func TestUsablePasskeysDropsBadEntries(t *testing.T) {
	good := passkeytest.New(t).Pin(t)
	bad := good
	bad.PublicKey = []byte("garbage")
	got := usablePasskeys([]sign.Passkey{bad, good}, slog.New(slog.DiscardHandler))
	if len(got) != 1 || string(got[0].PublicKey) != string(good.PublicKey) {
		t.Fatalf("got %+v", got)
	}
}

func TestMissingListMeansDefaults(t *testing.T) {
	var cfg Config
	if err := json.Unmarshal([]byte(`{"device_id":"x"}`), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.passkeyTypes()) != len(api.DefaultPasskeyTypes) {
		t.Fatalf("got %v", cfg.passkeyTypes())
	}
	if err := json.Unmarshal([]byte(`{"passkey_types":[]}`), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.passkeyTypes()) != 0 {
		t.Fatalf("got %v", cfg.passkeyTypes())
	}
}
