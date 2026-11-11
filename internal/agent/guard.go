package agent

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/sign"
)

// clockTolerance absorbs normal time corrections. A bigger jump backwards
// could bring expired tasks back to life.
const clockTolerance = 10 * time.Minute

const (
	// maxPasskeyLifetime stops envelopes with a far expiry early. It cannot
	// limit how long a server sits on an approval, because a server can wait
	// until the expiry is near. The freshness value does that.
	maxPasskeyLifetime = 24 * time.Hour
	// passkeyFreshness is how long a freshness value stays the current one. The
	// previous value still counts, so an approval works for up to twice this
	// long: 24 hours. A value that does not exist yet cannot be stockpiled.
	passkeyFreshness = 12 * time.Hour
	// maxPasskeyJump stops a server from pushing the counter so far that no
	// later approval fits above it.
	maxPasskeyJump = 1 << 20
	// A hacked dashboard can talk someone into touching their passkey again and
	// again and collect an approval each time. This bounds what that yields.
	maxPasskeyTasks   = 20
	passkeyTaskWindow = 24 * time.Hour
)

// Guard decides whether a task may run on a device with pinned signing keys.
// Everything it needs lives on the device, out of the server's reach.
type Guard struct {
	path string
	keys []ssh.PublicKey

	// passkeys and passkeyTypes stay empty until SetPasskeys.
	passkeys     []sign.Passkey
	passkeyTypes map[string]bool

	mu    sync.Mutex
	state guardState
}

// guardState survives restarts. Losing it would allow old tasks to run again,
// which is why a missing file is an error and not a fresh start.
type guardState struct {
	Counter  uint64    `json:"counter"`
	LastSeen time.Time `json:"last_seen"`
	// PasskeyCounter is apart from Counter, because the server chooses it.
	// Sharing one would let a hacked server stop all signed tasks with a single
	// approval, by setting a counter nothing can go above.
	PasskeyCounter uint64 `json:"passkey_counter,omitempty"`
	// PasskeyTimes holds the approvals of the last day, for a sliding limit.
	PasskeyTimes []time.Time `json:"passkey_times,omitempty"`
	// Freshness values an approval has to name.
	Freshness         string    `json:"freshness,omitempty"`
	PreviousFreshness string    `json:"previous_freshness,omitempty"`
	FreshnessAt       time.Time `json:"freshness_at,omitzero"`
}

// refresh replaces an aged freshness value. After a long time off, the previous
// value is dropped as well, because it would be older than the promised limit.
func (s *guardState) refresh(now time.Time) bool {
	age := now.Sub(s.FreshnessAt)
	if s.Freshness != "" && age < passkeyFreshness {
		return false
	}
	s.PreviousFreshness = ""
	if s.Freshness != "" && age < 2*passkeyFreshness {
		s.PreviousFreshness = s.Freshness
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		panic(err) // crypto/rand failing is not recoverable
	}
	s.Freshness = hex.EncodeToString(raw)
	s.FreshnessAt = now
	return true
}

func (s *guardState) fresh(value string) bool {
	return value != "" && (value == s.Freshness || value == s.PreviousFreshness)
}

// CreateGuard writes the initial state when keys are first pinned.
func CreateGuard(path string) error {
	return writeDurable(path, guardState{LastSeen: time.Now()})
}

// OpenGuard loads the state. It fails when the state is gone, and a device in
// that condition refuses tasks until an admin looks at it.
func OpenGuard(path string, lines []string) (*Guard, error) {
	g := &Guard{path: path}
	for _, line := range lines {
		key, err := sign.ParseKey(line)
		if err != nil {
			return nil, err
		}
		g.keys = append(g.keys, key)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signing state: %w", err)
	}
	if err := json.Unmarshal(raw, &g.state); err != nil {
		return nil, fmt.Errorf("signing state: %w", err)
	}
	return g, nil
}

// Counter is the highest accepted counter, for the admin tool.
func (g *Guard) Counter() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state.Counter
}

// SetKeys replaces the pinned keys in memory after a verified keys.set.
func (g *Guard) SetKeys(keys []ssh.PublicKey) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.keys = keys
}

// PasskeyCounter is the highest accepted passkey counter, for the report.
// Freshness returns the value new passkey approvals have to name. It goes out
// with the report, so a server learns it no earlier than it becomes valid.
func (g *Guard) Freshness(now time.Time) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	next := g.state
	if next.refresh(now) {
		if err := writeDurable(g.path, next); err != nil {
			return "", err
		}
		g.state = next
	}
	return g.state.Freshness, nil
}

func (g *Guard) PasskeyCounter() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state.PasskeyCounter
}

// SetPasskeys replaces the pinned passkeys and the task types they may approve.
// Types outside the ceiling in the api package stay refused, whatever the list
// says.
func (g *Guard) SetPasskeys(passkeys []sign.Passkey, types []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.passkeys = passkeys
	g.passkeyTypes = map[string]bool{}
	for _, taskType := range api.ExpandLegacyTypes(types) {
		if api.PasskeyEligible(taskType) {
			g.passkeyTypes[taskType] = true
		}
	}
}

// Passkeys reports the credential IDs and types in force, for the report.
func (g *Guard) Passkeys() (ids, types []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, p := range g.passkeys {
		ids = append(ids, base64.RawURLEncoding.EncodeToString(p.CredentialID))
	}
	for taskType := range g.passkeyTypes {
		types = append(types, taskType)
	}
	slices.Sort(types)
	return ids, types
}

// Admit returns the task to execute. For a signed task, that is built from the
// signed envelope alone, so nothing the server added can reach the system. The
// counter is stored durably before the task runs: a crash then loses a task at
// worst, and never allows it to run twice.
func (g *Guard) Admit(task api.Task, device string, now time.Time) (api.Task, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if now.Before(g.state.LastSeen.Add(-clockTolerance)) {
		return api.Task{}, fmt.Errorf("clock is behind the last seen time %s", g.state.LastSeen.Format(time.RFC3339))
	}
	if task.Signed == nil {
		if api.NeedsSignature(task.Type) {
			return api.Task{}, errors.New("task needs a signature on this device")
		}
		return task, nil
	}
	if task.Signed.Passkey != nil {
		return g.admitPasskey(task, device, now)
	}
	env, err := sign.Verify(*task.Signed, g.keys)
	if err != nil {
		return api.Task{}, err
	}
	if env.DeviceID != device {
		return api.Task{}, fmt.Errorf("task was signed for device %s", env.DeviceID)
	}
	if !now.Before(env.NotAfter) {
		return api.Task{}, errors.New("signed task has expired")
	}
	if err := approvalWindow(env, now); err != nil {
		return api.Task{}, err
	}
	if env.Counter <= g.state.Counter {
		return api.Task{}, fmt.Errorf("counter %d is not above %d", env.Counter, g.state.Counter)
	}
	next := g.state
	next.Counter = env.Counter
	next.LastSeen = laterOf(g.state.LastSeen, now)
	if err := writeDurable(g.path, next); err != nil {
		return api.Task{}, err
	}
	g.state = next
	return api.Task{ID: task.ID, Type: env.Type, Payload: env.Payload, Request: task.Request}, nil
}

// admitPasskey is Admit for a task approved in a browser. The server may have
// chosen every field of the envelope and shown the person something else, so
// on top of the signature, this limits what such an approval can reach. The
// caller holds the lock.
func (g *Guard) admitPasskey(task api.Task, device string, now time.Time) (api.Task, error) {
	env, passkey, err := sign.VerifyPasskey(*task.Signed, g.passkeys, now)
	if err != nil {
		return api.Task{}, err
	}
	if env.DeviceID != device {
		return api.Task{}, fmt.Errorf("task was approved for device %s", env.DeviceID)
	}
	if !now.Before(env.NotAfter) {
		return api.Task{}, errors.New("approved task has expired")
	}
	if env.NotAfter.After(now.Add(maxPasskeyLifetime)) {
		return api.Task{}, errors.New("approval is valid for too long")
	}
	if err := approvalWindow(env, now); err != nil {
		return api.Task{}, err
	}
	if !g.passkeyTypes[env.Type] {
		return api.Task{}, fmt.Errorf("a passkey may not approve %s on this device", env.Type)
	}
	if err := api.PasskeyLimits(env.Type, env.Payload, now); err != nil {
		return api.Task{}, err
	}
	if env.Counter <= g.state.PasskeyCounter {
		return api.Task{}, fmt.Errorf("counter %d is not above %d", env.Counter, g.state.PasskeyCounter)
	}
	if env.Counter-g.state.PasskeyCounter > maxPasskeyJump {
		return api.Task{}, fmt.Errorf("counter %d is too far above %d", env.Counter, g.state.PasskeyCounter)
	}
	next := g.state
	next.refresh(now)
	if !next.fresh(env.Freshness) {
		return api.Task{}, errors.New("approval is too old or was not made for this device state")
	}
	recent := make([]time.Time, 0, maxPasskeyTasks)
	for _, at := range next.PasskeyTimes {
		if now.Before(at.Add(passkeyTaskWindow)) {
			recent = append(recent, at)
		}
	}
	if len(recent) >= maxPasskeyTasks {
		return api.Task{}, fmt.Errorf("more than %d passkey approvals within a day", maxPasskeyTasks)
	}
	next.PasskeyTimes = append(recent, now)
	next.PasskeyCounter = env.Counter
	next.LastSeen = laterOf(g.state.LastSeen, now)
	if err := writeDurable(g.path, next); err != nil {
		return api.Task{}, err
	}
	g.state = next
	return api.Task{ID: task.ID, Type: env.Type, Payload: env.Payload, Approver: passkey.Name, Request: task.Request}, nil
}

// approvalWindow refuses an approval that reaches further ahead than its type
// allows, such as a live terminal that must start now.
func approvalWindow(env sign.Envelope, now time.Time) error {
	window := api.ApprovalWindow(env.Type)
	if window > 0 && env.NotAfter.After(now.Add(window)) {
		return api.Fail(api.ErrTerminalApproval, window.String())
	}
	return nil
}

// Touch moves the last seen time forward, so that a later clock rollback shows.
func (g *Guard) Touch(now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !now.After(g.state.LastSeen) {
		return nil
	}
	next := g.state
	next.LastSeen = now
	if err := writeDurable(g.path, next); err != nil {
		return err
	}
	g.state = next
	return nil
}

func laterOf(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func writeDurable(path string, state guardState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeAtomicSync(path, raw, 0o600)
}
