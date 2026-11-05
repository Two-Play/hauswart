package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/philippe/hauswart/internal/api"
	"github.com/philippe/hauswart/internal/sign"
)

// clockTolerance absorbs normal time corrections. A bigger jump backwards
// could bring expired tasks back to life.
const clockTolerance = 10 * time.Minute

// Guard decides whether a task may run on a device with pinned signing keys.
// Everything it needs lives on the device, out of the server's reach.
type Guard struct {
	path string
	keys []ssh.PublicKey

	mu    sync.Mutex
	state guardState
}

// guardState survives restarts. Losing it would allow old tasks to run again,
// which is why a missing file is an error and not a fresh start.
type guardState struct {
	Counter  uint64    `json:"counter"`
	LastSeen time.Time `json:"last_seen"`
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
	if env.Counter <= g.state.Counter {
		return api.Task{}, fmt.Errorf("counter %d is not above %d", env.Counter, g.state.Counter)
	}
	next := guardState{Counter: env.Counter, LastSeen: laterOf(g.state.LastSeen, now)}
	if err := writeDurable(g.path, next); err != nil {
		return api.Task{}, err
	}
	g.state = next
	return api.Task{ID: task.ID, Type: env.Type, Payload: env.Payload}, nil
}

// Touch moves the last seen time forward, so that a later clock rollback shows.
func (g *Guard) Touch(now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !now.After(g.state.LastSeen) {
		return nil
	}
	next := guardState{Counter: g.state.Counter, LastSeen: now}
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
