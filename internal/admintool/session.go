package admintool

import (
	"crypto/sha256"
	"errors"
	"fmt"

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

	payload []byte
}

// prepare turns a task from the server into what is shown. Nothing from the server
// reaches the signature except through review.
func prepare(cfg *config, list map[string]serverDevice, task queued, rest []queued) Item {
	item := Item{ID: task.ID, DeviceID: clean(task.DeviceID), Type: clean(task.Type), CreatedBy: clean(task.CreatedBy)}
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
		item.Changes = policyChanges(task.DeviceID, task.Type, payload)
		item.Warning = policyWarning(cfg, task.Type, payload)
		item.Others = identicalPolicies(cfg, rest, item.Group)
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
	if item.Group != "" {
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
	return s, nil
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
		items = append(items, prepare(s.cfg, list, task, queue[i+1:]))
	}
	return items, nil
}

// Sign signs what was shown. The queue is read again and reviewed again, and
// anything that differs from what the admin looked at is refused.
func (s *Session) Sign(shown Item) error {
	if shown.Problem != "" {
		return errors.New(shown.Problem)
	}
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
		now := prepare(s.cfg, list, task, queue[i+1:])
		if now.Problem != "" || now.digest() != shown.digest() {
			return ErrChanged
		}
		key, err := s.signer()
		if err != nil {
			return err
		}
		return s.sign(key, list, now)
	}
	return ErrChanged
}

// Reject closes a task without signing it.
func (s *Session) Reject(item Item) error {
	return s.cfg.call("POST", "/api/tasks/"+item.ID+"/reject", struct{}{}, nil)
}

// NameDevice gives a device its name on this computer.
func (s *Session) NameDevice(id, name string) error {
	if !api.ValidText(name, 64) || name == "" {
		return errors.New("that is not a usable name")
	}
	known := s.cfg.Devices[id]
	if known == nil {
		known = &device{}
		s.cfg.Devices[id] = known
	}
	known.Name = name
	return s.cfg.save()
}

// LogIn renews the session with the server this computer already trusts.
func (s *Session) LogIn(user, password string) error { return s.cfg.logIn(user, password) }
