package admintool

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Two-Play/hauswart/internal/api"
)

func testSession(t *testing.T, queue *[]queued) (*Session, *[]Item) {
	t.Helper()
	t.Setenv("HAUSWART_ADMIN_DIR", t.TempDir())
	cfg := &config{Server: "https://test", Devices: map[string]*device{"dev": {Name: "laptop"}}}
	if err := cfg.save(); err != nil {
		t.Fatal(err)
	}
	var signed []Item
	return &Session{
		cfg:     cfg,
		queue:   func() ([]queued, error) { return *queue, nil },
		devices: func() (map[string]serverDevice, error) { return map[string]serverDevice{}, nil },
		signer:  func() (ssh.Signer, error) { return nil, nil },
		sign: func(_ ssh.Signer, _ map[string]serverDevice, item Item) error {
			signed = append(signed, item)
			return nil
		},
	}, &signed
}

func install(pkg string) queued {
	raw, _ := json.Marshal(api.PackagesPayload{Packages: []string{pkg}})
	return queued{ID: "t1", DeviceID: "dev", Type: api.TaskPkgInstall, Payload: raw, CreatedBy: "admin"}
}

func TestSignsWhatWasShown(t *testing.T) {
	queue := []queued{install("vim")}
	s, signed := testSession(t, &queue)
	items, err := s.Items()
	if err != nil || len(items) != 1 || !strings.Contains(items[0].Text, "vim") {
		t.Fatalf("%+v, %v", items, err)
	}
	if err := s.Sign(items[0]); err != nil {
		t.Fatal(err)
	}
	if len(*signed) != 1 || string((*signed)[0].payload) != `{"packages":["vim"]}` {
		t.Fatalf("got %+v", *signed)
	}
}

// The server may swap a task while the admin is reading it.
func TestRefusesATaskThatChanged(t *testing.T) {
	queue := []queued{install("vim")}
	s, signed := testSession(t, &queue)
	items, _ := s.Items()
	queue[0] = install("evil")
	if err := s.Sign(items[0]); !errors.Is(err, ErrChanged) {
		t.Fatalf("got %v", err)
	}
	queue[0] = install("vim")
	queue[0].Type = api.TaskPkgRemove
	if err := s.Sign(items[0]); !errors.Is(err, ErrChanged) {
		t.Fatalf("got %v", err)
	}
	queue[0] = install("vim")
	queue[0].DeviceID = "other"
	if err := s.Sign(items[0]); !errors.Is(err, ErrChanged) {
		t.Fatalf("got %v", err)
	}
	queue = nil
	if err := s.Sign(items[0]); !errors.Is(err, ErrChanged) {
		t.Fatalf("got %v", err)
	}
	if len(*signed) != 0 {
		t.Fatalf("signed %+v", *signed)
	}
}

func TestUnnamedDeviceCannotBeSignedForUntilNamed(t *testing.T) {
	queue := []queued{install("vim")}
	queue[0].DeviceID = "new"
	s, signed := testSession(t, &queue)
	items, _ := s.Items()
	if !items[0].Unnamed || s.Sign(items[0]) == nil || len(*signed) != 0 {
		t.Fatalf("got %+v", items[0])
	}
	if err := s.NameDevice("new", "kinder-pc"); err != nil {
		t.Fatal(err)
	}
	items, _ = s.Items()
	if items[0].Problem != "" || items[0].DeviceName != "kinder-pc" {
		t.Fatalf("got %+v", items[0])
	}
	if s.NameDevice("x", "bad\x1b[2Kname") == nil || s.NameDevice("x", "") == nil {
		t.Fatal("accepted a bad name")
	}
}

// The command line tool may sign while the app is open.
func TestCountersComeFromTheFile(t *testing.T) {
	queue := []queued{install("vim")}
	s, _ := testSession(t, &queue)
	other, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	other.Devices["dev"].Counter = 40
	if err := other.save(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Items(); err != nil {
		t.Fatal(err)
	}
	if s.cfg.Devices["dev"].Counter != 40 {
		t.Fatalf("got %d", s.cfg.Devices["dev"].Counter)
	}
}

func TestTextFromTheServerIsCleaned(t *testing.T) {
	queue := []queued{install("vim")}
	queue[0].CreatedBy = "admin\x1b[2K"
	s, _ := testSession(t, &queue)
	items, _ := s.Items()
	if strings.ContainsRune(items[0].CreatedBy, 0x1b) {
		t.Fatalf("got %q", items[0].CreatedBy)
	}
}
