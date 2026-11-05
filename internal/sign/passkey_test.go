package sign_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/philippe/hauswart/internal/sign"
	"github.com/philippe/hauswart/internal/sign/passkeytest"
)

func envelope(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(sign.Envelope{
		Type: "pkg.install", Payload: json.RawMessage(`{"packages":["vim"]}`),
		DeviceID: "device", Counter: 1, NotAfter: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifyPasskey(t *testing.T) {
	a := passkeytest.New(t)
	raw := envelope(t)
	env, pin, err := sign.VerifyPasskey(sign.Signed{Envelope: raw, Passkey: a.Assert(t, raw)}, []sign.Passkey{a.Pin(t)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if env.Type != "pkg.install" || pin.Name != "phone" {
		t.Fatalf("got %+v %+v", env, pin)
	}
}

func TestVerifyPasskeyEd25519(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := passkeytest.New(t)
	raw := envelope(t)
	assertion := a.Assert(t, raw)
	hash := sha256.Sum256(assertion.ClientDataJSON)
	assertion.Signature = ed25519.Sign(private, append(append([]byte{}, assertion.AuthenticatorData...), hash[:]...))
	pin := a.Pin(t)
	if pin.PublicKey, err = x509.MarshalPKIXPublicKey(public); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sign.VerifyPasskey(sign.Signed{Envelope: raw, Passkey: assertion}, []sign.Passkey{pin}, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPasskeyRejects(t *testing.T) {
	cases := map[string]func(a *passkeytest.Authenticator){
		"wrong origin":      func(a *passkeytest.Authenticator) { a.Origin = "https://evil.example" },
		"other port":        func(a *passkeytest.Authenticator) { a.Origin = "https://hauswart.home.arpa:9443" },
		"plain http":        func(a *passkeytest.Authenticator) { a.Origin = "http://hauswart.home.arpa:8443" },
		"wrong RP ID":       func(a *passkeytest.Authenticator) { a.RPID = "home.arpa" },
		"registration":      func(a *passkeytest.Authenticator) { a.Type = "webauthn.create" },
		"no user presence":  func(a *passkeytest.Authenticator) { a.Flags = 0x04 },
		"no verification":   func(a *passkeytest.Authenticator) { a.Flags = 0x01 },
		"cross origin":      func(a *passkeytest.Authenticator) { a.ExtraJSON = `{"crossOrigin":true}` },
		"embedded in a top": func(a *passkeytest.Authenticator) { a.ExtraJSON = `{"topOrigin":"https://evil.example"}` },
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			a := passkeytest.New(t)
			pin := a.Pin(t)
			spoil(a)
			raw := envelope(t)
			if _, _, err := sign.VerifyPasskey(sign.Signed{Envelope: raw, Passkey: a.Assert(t, raw)}, []sign.Passkey{pin}, time.Now()); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// Browsers add fields of their own, which must not break anything.
func TestVerifyPasskeyAllowsExtraClientFields(t *testing.T) {
	a := passkeytest.New(t)
	a.ExtraJSON = `{"crossOrigin":false,"other_keys_can_be_added_here":"x"}`
	raw := envelope(t)
	if _, _, err := sign.VerifyPasskey(sign.Signed{Envelope: raw, Passkey: a.Assert(t, raw)}, []sign.Passkey{a.Pin(t)}, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPasskeyRejectsChangedEnvelope(t *testing.T) {
	a := passkeytest.New(t)
	raw := envelope(t)
	assertion := a.Assert(t, raw)
	changed := []byte(strings.Replace(string(raw), "vim", "nmap", 1))
	if _, _, err := sign.VerifyPasskey(sign.Signed{Envelope: changed, Passkey: assertion}, []sign.Passkey{a.Pin(t)}, time.Now()); err == nil {
		t.Fatal("accepted a changed envelope")
	}
}

// Without the namespace, an assertion over the plain hash of an envelope from
// some other use of the credential would count.
func TestVerifyPasskeyRejectsChallengeWithoutNamespace(t *testing.T) {
	a := passkeytest.New(t)
	raw := envelope(t)
	plain := sha256.Sum256(raw)
	if _, _, err := sign.VerifyPasskey(sign.Signed{Envelope: raw, Passkey: a.AssertChallenge(t, plain[:])}, []sign.Passkey{a.Pin(t)}, time.Now()); err == nil {
		t.Fatal("accepted")
	}
}

func TestVerifyPasskeyRejectsForeignAndExpiredPins(t *testing.T) {
	a, other := passkeytest.New(t), passkeytest.New(t)
	raw := envelope(t)
	signed := sign.Signed{Envelope: raw, Passkey: a.Assert(t, raw)}
	if _, _, err := sign.VerifyPasskey(signed, []sign.Passkey{other.Pin(t)}, time.Now()); err == nil {
		t.Fatal("accepted a passkey that is not pinned")
	}
	if _, _, err := sign.VerifyPasskey(signed, nil, time.Now()); err == nil {
		t.Fatal("accepted without pins")
	}
	// The right credential ID with another key must not pass either.
	swapped := other.Pin(t)
	swapped.CredentialID = a.CredentialID
	if _, _, err := sign.VerifyPasskey(signed, []sign.Passkey{swapped}, time.Now()); err == nil {
		t.Fatal("accepted a signature of another key")
	}
	if _, _, err := sign.VerifyPasskey(signed, []sign.Passkey{a.Pin(t)}, time.Now().Add(48*time.Hour)); err == nil {
		t.Fatal("accepted an expired pin")
	}
}

func TestVerifyPasskeyRejectsTwoApprovals(t *testing.T) {
	a := passkeytest.New(t)
	raw := envelope(t)
	signed := sign.Signed{Envelope: raw, Signature: []byte("x"), Passkey: a.Assert(t, raw)}
	if _, _, err := sign.VerifyPasskey(signed, []sign.Passkey{a.Pin(t)}, time.Now()); err == nil {
		t.Fatal("accepted")
	}
	if _, err := sign.Verify(signed, nil); err == nil {
		t.Fatal("accepted on the signature path")
	}
}

func TestVerifyPasskeySurvivesGarbage(t *testing.T) {
	a := passkeytest.New(t)
	raw := envelope(t)
	good := a.Assert(t, raw)
	for name, bad := range map[string]sign.Assertion{
		"short auth data": {CredentialID: good.CredentialID, AuthenticatorData: []byte{1}, ClientDataJSON: good.ClientDataJSON, Signature: good.Signature},
		"no signature":    {CredentialID: good.CredentialID, AuthenticatorData: good.AuthenticatorData, ClientDataJSON: good.ClientDataJSON},
		"empty":           {},
	} {
		if _, _, err := sign.VerifyPasskey(sign.Signed{Envelope: raw, Passkey: &bad}, []sign.Passkey{a.Pin(t)}, time.Now()); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// A signed short auth data still has to be refused, not panic.
func TestVerifyPasskeyShortAuthDataWithValidSignature(t *testing.T) {
	a := passkeytest.New(t)
	raw := envelope(t)
	assertion := a.Assert(t, raw)
	assertion.AuthenticatorData = []byte{1, 2, 3}
	hash := sha256.Sum256(assertion.ClientDataJSON)
	digest := sha256.Sum256(append(append([]byte{}, assertion.AuthenticatorData...), hash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.Key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	assertion.Signature = sig
	if _, _, err := sign.VerifyPasskey(sign.Signed{Envelope: raw, Passkey: assertion}, []sign.Passkey{a.Pin(t)}, time.Now()); err == nil {
		t.Fatal("accepted")
	}
}

func TestValidPasskey(t *testing.T) {
	a := passkeytest.New(t)
	if err := sign.ValidPasskey(a.Pin(t)); err != nil {
		t.Fatal(err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384DER, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	cases := map[string]func(p *sign.Passkey){
		"IP origin":       func(p *sign.Passkey) { p.Origin, p.RPID = "https://10.8.0.1:8443", "10.8.0.1" },
		"http origin":     func(p *sign.Passkey) { p.Origin = "http://hauswart.home.arpa:8443" },
		"origin path":     func(p *sign.Passkey) { p.Origin += "/x" },
		"upper case":      func(p *sign.Passkey) { p.Origin = "https://Hauswart.home.arpa:8443" },
		"parent RP":       func(p *sign.Passkey) { p.RPID = "home.arpa" },
		"P-384":           func(p *sign.Passkey) { p.PublicKey = p384DER },
		"RSA":             func(p *sign.Passkey) { p.PublicKey = rsaDER },
		"garbage key":     func(p *sign.Passkey) { p.PublicKey = []byte("x") },
		"no credential":   func(p *sign.Passkey) { p.CredentialID = nil },
		"long credential": func(p *sign.Passkey) { p.CredentialID = make([]byte, 2000) },
		"no name":         func(p *sign.Passkey) { p.Name = "" },
		"control name":    func(p *sign.Passkey) { p.Name = "a\x1b[2Jb" },
		"no expiry":       func(p *sign.Passkey) { p.NotAfter = time.Time{} },
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			p := a.Pin(t)
			spoil(&p)
			if err := sign.ValidPasskey(p); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestPasskeyChallengeMatchesWhatTheBrowserComputes(t *testing.T) {
	want := sha256.Sum256([]byte("hauswart-task-passkey@v1\x00envelope"))
	if got := sign.PasskeyChallenge([]byte("envelope")); base64.StdEncoding.EncodeToString(got) != base64.StdEncoding.EncodeToString(want[:]) {
		t.Fatal("the dashboard computes this hash too, keep them the same")
	}
}
