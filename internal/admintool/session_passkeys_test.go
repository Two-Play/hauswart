package admintool

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/sign"
	"github.com/Two-Play/hauswart/internal/sign/passkeytest"
)

type sentPins struct {
	device string
	pins   []sign.Passkey
}

func pinSession(t *testing.T, server *[]serverPasskey) (*Session, *[]sentPins) {
	t.Helper()
	t.Setenv("HAUSWART_ADMIN_DIR", t.TempDir())
	cfg := &config{Server: passkeytest.Origin, Devices: map[string]*device{
		"dev":     {Name: "laptop"},
		"unnamed": {},
	}}
	if err := cfg.save(); err != nil {
		t.Fatal(err)
	}
	protected := &api.Report{Protected: true}
	var sent []sentPins
	s := &Session{
		cfg:   cfg,
		queue: func() ([]queued, error) { return nil, nil },
		devices: func() (map[string]serverDevice, error) {
			return map[string]serverDevice{
				"dev":     {ID: "dev", Report: protected},
				"unnamed": {ID: "unnamed", Report: protected},
			}, nil
		},
		signer:      func() (ssh.Signer, error) { return nil, nil },
		passkeyList: func() ([]serverPasskey, error) { return *server, nil },
	}
	s.pinSend = func(_ ssh.Signer, _ map[string]serverDevice, id string, pins []sign.Passkey) error {
		sent = append(sent, sentPins{id, pins})
		return rememberPins(s.cfg, id, pins)
	}
	return s, &sent
}

func TestPinsWhatWasShownAndRemembersIt(t *testing.T) {
	server := []serverPasskey{candidateFixture(t)}
	s, sent := pinSession(t, &server)
	state, err := s.Pins()
	if err != nil || len(state.Passkeys) != 1 || len(state.Devices) != 1 || state.Passkeys[0].Problem != "" {
		t.Fatalf("%+v, %v", state, err)
	}
	change := PinChange{Passkey: state.Passkeys[0].Key, Devices: []string{"dev"}}
	text, err := s.PinPreview(change)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"laptop", state.Passkeys[0].Fingerprint, "Flatpak"} {
		if !strings.Contains(text, want) {
			t.Fatalf("%q misses %q", text, want)
		}
	}
	if err := s.Pin(change, text); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 1 || (*sent)[0].device != "dev" || len((*sent)[0].pins) != 1 {
		t.Fatalf("sent %+v", *sent)
	}
	state, err = s.Pins()
	if err != nil || len(state.Passkeys) != 1 || len(state.Passkeys[0].PinnedOn) != 1 {
		t.Fatalf("%+v, %v", state, err)
	}

	// Gone from the server, it still shows, and can be removed.
	server = nil
	state, err = s.Pins()
	if err != nil || len(state.Passkeys) != 1 || state.Passkeys[0].Problem == "" {
		t.Fatalf("%+v, %v", state, err)
	}
	remove := PinChange{Passkey: state.Passkeys[0].Key, Devices: []string{"dev"}, Remove: true}
	text, err = s.PinPreview(remove)
	if err != nil || !strings.Contains(text, "none") {
		t.Fatalf("%q, %v", text, err)
	}
	if err := s.Pin(remove, text); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 2 || len((*sent)[1].pins) != 0 {
		t.Fatalf("sent %+v", *sent)
	}
}

// The server may swap the passkey between the preview and the signature.
func TestPinRefusesWhatChanged(t *testing.T) {
	server := []serverPasskey{candidateFixture(t)}
	s, sent := pinSession(t, &server)
	change := PinChange{Passkey: passkeyKey(server[0].CredentialID), Devices: []string{"dev"}}
	text, err := s.PinPreview(change)
	if err != nil {
		t.Fatal(err)
	}
	other := candidateFixture(t)
	server[0].PublicKey = other.PublicKey
	if err := s.Pin(change, text); !errors.Is(err, ErrChanged) {
		t.Fatalf("got %v", err)
	}
	if len(*sent) != 0 {
		t.Fatalf("sent %+v", *sent)
	}
}

func TestPinRefuses(t *testing.T) {
	cases := map[string]func(*[]serverPasskey, *PinChange){
		"unnamed device": func(_ *[]serverPasskey, c *PinChange) { c.Devices = []string{"unnamed"} },
		"unknown device": func(_ *[]serverPasskey, c *PinChange) { c.Devices = []string{"nope"} },
		"no device":      func(_ *[]serverPasskey, c *PinChange) { c.Devices = nil },
		"foreign origin": func(s *[]serverPasskey, _ *PinChange) {
			(*s)[0].Origin, (*s)[0].RPID = "https://evil.example", "evil.example"
		},
		"not on server": func(s *[]serverPasskey, _ *PinChange) { *s = nil },
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			server := []serverPasskey{candidateFixture(t)}
			s, _ := pinSession(t, &server)
			change := PinChange{Passkey: passkeyKey(server[0].CredentialID), Devices: []string{"dev"}}
			spoil(&server, &change)
			if _, err := s.PinPreview(change); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestPinRefusesTooMany(t *testing.T) {
	server := []serverPasskey{candidateFixture(t)}
	s, _ := pinSession(t, &server)
	for range sign.MaxPasskeys {
		s.cfg.Devices["dev"].Passkeys = append(s.cfg.Devices["dev"].Passkeys, passkeytest.New(t).Pin(t))
	}
	if err := s.cfg.save(); err != nil {
		t.Fatal(err)
	}
	change := PinChange{Passkey: passkeyKey(server[0].CredentialID), Devices: []string{"dev"}}
	if _, err := s.PinPreview(change); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("got %v", err)
	}
}
