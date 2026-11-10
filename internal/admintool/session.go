package admintool

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Two-Play/hauswart/internal/api"
)

// ErrChanged says that a task is no longer what was shown. It is not signed then.
var ErrChanged = errors.New("this task changed on the server since it was shown, look at it again")

// Item is a waiting task the way an admin reviews it, in the terminal or in the
// app. Both get it from here, so they show the same.
type Item struct {
	ID         string
	DeviceID   string
	DeviceName string
	Type       string
	CreatedBy  string
	// Text is what would be signed, in words.
	Text string
	// Changes and Warning are for policies.
	Changes string
	Warning string
	// Others says what the same policy would do on other waiting devices.
	Others []string
	// Group is the same for tasks that sign the same thing, and empty for all
	// but policies.
	Group string
	// Problem says why this cannot be signed. Everything else is empty then.
	Problem string
	// Unnamed says that naming the device would solve the problem, and
	// ServerName is what the server calls it, which proves nothing.
	Unnamed    bool
	ServerName string

	// What follows is context from the server and the device. It helps to
	// decide, but proves nothing and is not signed.
	CreatedAt time.Time
	// Request is the request the task was made for, nil if there was none.
	Request  *Request
	Hostname string
	LastSeen time.Time
	Sessions []LoggedIn

	payload []byte
}

// Request is who asked for a task, and why.
type Request struct {
	User   string
	Reason string
	At     time.Time
}

// LoggedIn is someone logged in on the device. Active is the one in front.
type LoggedIn struct {
	User   string
	Active bool
}

// Automatic says that a rule approved the request without anyone looking.
func (i Item) Automatic() bool { return strings.HasPrefix(i.CreatedBy, api.DecidedAutomatically+":") }

// maxReason is how much of a reason is shown.
const maxReason = 300

// cleanReason keeps a reason on one line and free of control characters.
func cleanReason(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > maxReason {
		s = string(r[:maxReason]) + "…"
	}
	return clean(s)
}

// unix turns a time from the server into one, zero for none.
func unix(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

// addContext copies what the server says around a task, cleaned.
func addContext(item *Item, task queued) {
	item.CreatedAt = unix(task.CreatedAt)
	item.Hostname = clean(task.Hostname)
	item.LastSeen = unix(task.LastSeen)
	for _, s := range task.Sessions {
		if len(item.Sessions) == api.MaxReportSessions {
			break
		}
		item.Sessions = append(item.Sessions, LoggedIn{User: clean(s.User), Active: s.Active})
	}
	if r := task.Request; r != nil {
		item.Request = &Request{User: clean(r.User), Reason: cleanReason(r.Reason), At: unix(r.CreatedAt)}
	}
}

// prepare turns a task from the server into what is shown. Nothing from the server
// reaches the signature except through review.
func prepare(cfg *config, list map[string]serverDevice, task queued, rest []queued) Item {
	item := Item{ID: task.ID, DeviceID: clean(task.DeviceID), Type: clean(task.Type), CreatedBy: clean(task.CreatedBy)}
	addContext(&item, task)
	known := cfg.Devices[task.DeviceID]
	if known == nil || known.Name == "" {
		item.Unnamed = true
		item.ServerName = clean(list[task.DeviceID].Hostname)
		item.Problem = fmt.Sprintf("Skipped: device %s has no name here. Server calls it %q.", item.DeviceID, item.ServerName)
		return item
	}
	item.DeviceName = clean(known.Name)
	text, payload, err := review(task.Type, task.Payload)
	if err != nil {
		item.Problem = fmt.Sprintf("Skipped, cannot sign this: %v", err)
		return item
	}
	item.Text, item.payload = text, payload
	item.Group = policyFingerprint(task.Type, payload)
	if item.Group != "" {
		item.Changes = changesOf(list, task.DeviceID, task.Type, payload)
		item.Warning = policyWarning(cfg, task.Type, payload)
		item.Others = identicalPolicies(cfg, list, rest, item.Group)
	}
	return item
}

// digest stands for everything a signature would say.
func (i Item) digest() [sha256.Size]byte {
	return sha256.Sum256(fmt.Appendf(nil, "%s\x00%s\x00%s\x00%s", i.ID, i.Type, i.DeviceID, i.payload))
}

func signItem(cfg *config, key ssh.Signer, list map[string]serverDevice, item Item) error {
	signed, err := seal(cfg, key, item.DeviceID, list[item.DeviceID].Report, item.Type, item.payload, signedUntil(item.Type, item.payload))
	if err != nil {
		return err
	}
	if err := cfg.call("POST", "/api/tasks/"+item.ID+"/signature", signed, nil); err != nil {
		return err
	}
	if item.Type == api.TaskPolicySet || item.Type == api.TaskPolicyClear {
		return rememberPolicy(item.DeviceID, item.Type, item.payload)
	}
	return nil
}

// Session is the admin tool for a program that stays open.
type Session struct {
	cfg *config
	// These are the ways to the server, which tests replace.
	queue   func() ([]queued, error)
	devices func() (map[string]serverDevice, error)
	sign    func(ssh.Signer, map[string]serverDevice, Item) error
	signer  func() (ssh.Signer, error)
	schema  func() (string, error)

	// mu keeps one thing going at a time, as all of it changes cfg.
	mu sync.Mutex
	// key stays, as every signer holds a connection to the ssh-agent.
	key ssh.Signer
}

// others is the queue without one task. In a window, unlike in the terminal, any
// task can be picked first, and all the others are still ahead.
func others(queue []queued, i int) []queued {
	return slices.Delete(slices.Clone(queue), i, i+1)
}

// Open reads the settings of this computer.
func Open() (*Session, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	if cfg.Server == "" {
		return nil, errors.New("not logged in, run hauswart-admin login once")
	}
	s := &Session{cfg: cfg}
	s.queue = func() ([]queued, error) {
		var queue []queued
		return queue, cfg.call("GET", "/api/signing", nil, &queue)
	}
	s.devices = func() (map[string]serverDevice, error) { return fetchDevices(cfg) }
	s.sign = func(key ssh.Signer, list map[string]serverDevice, item Item) error {
		return signItem(cfg, key, list, item)
	}
	s.signer = func() (ssh.Signer, error) { return signer(cfg) }
	s.schema = func() (string, error) { return serverSchema(cfg) }
	return s, nil
}

// Outdated says, in a sentence, whether this program knows other tasks than
// the server, and so may refuse some. Empty if they agree.
func (s *Session) Outdated() string {
	if s.schema == nil {
		return ""
	}
	schema, err := s.schema()
	if err != nil {
		return ""
	}
	return schemaWarning(schema)
}

// reload reads the settings again. The command line tool may have signed in the
// meantime, and a counter must never go backwards.
func (s *Session) reload() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	*s.cfg = *cfg
	return nil
}

// Server says which server this computer is logged in to.
func (s *Session) Server() string { return s.cfg.Server }

// Items lists what waits for a signature.
func (s *Session) Items() ([]Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reload(); err != nil {
		return nil, err
	}
	queue, err := s.queue()
	if err != nil {
		return nil, err
	}
	list, err := s.devices()
	if err != nil {
		return nil, err
	}
	items := make([]Item, 0, len(queue))
	for i, task := range queue {
		items = append(items, prepare(s.cfg, list, task, others(queue, i)))
	}
	return items, nil
}

// Sign signs what was shown. The queue is read again and reviewed again, and
// anything that differs from what the admin looked at is refused.
func (s *Session) Sign(shown Item) error {
	if shown.Problem != "" {
		return errors.New(shown.Problem)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reload(); err != nil {
		return err
	}
	queue, err := s.queue()
	if err != nil {
		return err
	}
	list, err := s.devices()
	if err != nil {
		return err
	}
	for i, task := range queue {
		if task.ID != shown.ID {
			continue
		}
		now := prepare(s.cfg, list, task, others(queue, i))
		if now.Problem != "" || now.digest() != shown.digest() {
			return ErrChanged
		}
		if s.key == nil {
			if s.key, err = s.signer(); err != nil {
				return err
			}
		}
		err := s.sign(s.key, list, now)
		if err != nil {
			s.key = nil // the ssh-agent may have been restarted
		}
		return err
	}
	return ErrChanged
}

// Reject closes a task without signing it.
func (s *Session) Reject(item Item) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.call("POST", "/api/tasks/"+item.ID+"/reject", struct{}{}, nil)
}

// NameDevice gives a device its name on this computer.
func (s *Session) NameDevice(id, name string) error {
	if !api.ValidText(name, 64) || name == "" {
		return errors.New("that is not a usable name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return updateConfig(func(fresh *config) {
		known := fresh.Devices[id]
		if known == nil {
			known = &device{}
			fresh.Devices[id] = known
		}
		known.Name = name
		*s.cfg = *fresh
	})
}

// LogIn renews the session with the server this computer already trusts.
func (s *Session) LogIn(user, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reload(); err != nil {
		return err
	}
	return s.cfg.logIn(user, password)
}
