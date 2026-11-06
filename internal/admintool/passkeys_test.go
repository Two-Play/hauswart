package admintool

import (
	"strings"
	"testing"
	"time"

	"github.com/Two-Play/hauswart/internal/sign/passkeytest"
)

func candidateFixture(t *testing.T) serverPasskey {
	t.Helper()
	pin := passkeytest.New(t).Pin(t)
	return serverPasskey{
		ID: 1, Username: "mama", Name: pin.Name, CredentialID: pin.CredentialID,
		PublicKey: pin.PublicKey, RPID: pin.RPID, Origin: pin.Origin,
	}
}

func TestCandidateAcceptsThisServer(t *testing.T) {
	cfg := &config{Server: passkeytest.Origin}
	expiry := time.Now().Add(time.Hour)
	pin, err := candidate(cfg, candidateFixture(t), expiry)
	if err != nil {
		t.Fatal(err)
	}
	if !pin.NotAfter.Equal(expiry) {
		t.Fatalf("expiry %v", pin.NotAfter)
	}
}

// The server must not get a passkey of another site pinned on a device.
func TestCandidateRefusesWhatDoesNotBelongHere(t *testing.T) {
	cfg := &config{Server: passkeytest.Origin}
	cases := map[string]func(*serverPasskey){
		"other origin": func(p *serverPasskey) { p.Origin, p.RPID = "https://evil.example", "evil.example" },
		"parent RP":    func(p *serverPasskey) { p.RPID = "home.arpa" },
		"IP":           func(p *serverPasskey) { p.Origin, p.RPID = "https://10.8.0.1:8443", "10.8.0.1" },
		"bad key":      func(p *serverPasskey) { p.PublicKey = []byte("x") },
		"escape":       func(p *serverPasskey) { p.Name = "\x1b[2Jfake" },
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			p := candidateFixture(t)
			spoil(&p)
			if _, err := candidate(cfg, p, time.Now().Add(time.Hour)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestConfirmNeedsAClearYes(t *testing.T) {
	for answer, want := range map[string]bool{"y\n": true, "Y\n": true, "\n": false, "yes\n": false, "": false} {
		got, err := confirm(strings.NewReader(answer), "?")
		if err != nil || got != want {
			t.Errorf("%q: %v %v", answer, got, err)
		}
	}
}
