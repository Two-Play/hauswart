package sign

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func newSigner(t *testing.T) ssh.Signer {
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

func envelope() Envelope {
	return Envelope{
		Type:     "pkg.install",
		Payload:  json.RawMessage(`{"packages":["vim"]}`),
		DeviceID: "device",
		Counter:  1,
		NotAfter: time.Now().Add(time.Hour),
	}
}

func TestRoundTrip(t *testing.T) {
	signer := newSigner(t)
	signed, err := Sign(signer, envelope())
	if err != nil {
		t.Fatal(err)
	}
	env, err := Verify(signed, []ssh.PublicKey{signer.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	if env.Type != "pkg.install" || env.DeviceID != "device" || env.Counter != 1 {
		t.Fatalf("got %+v", env)
	}
}

func TestAnyPinnedKeyVerifies(t *testing.T) {
	first, second := newSigner(t), newSigner(t)
	signed, err := Sign(second, envelope())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(signed, []ssh.PublicKey{first.PublicKey(), second.PublicKey()}); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsTampering(t *testing.T) {
	signer := newSigner(t)
	keys := []ssh.PublicKey{signer.PublicKey()}
	signed, err := Sign(signer, envelope())
	if err != nil {
		t.Fatal(err)
	}

	changed := signed
	changed.Envelope = []byte(strings.Replace(string(signed.Envelope), "vim", "nmap", 1))
	if _, err := Verify(changed, keys); err == nil {
		t.Error("accepted a changed payload")
	}
	changed = signed
	changed.Envelope = []byte(strings.Replace(string(signed.Envelope), `"counter":1`, `"counter":2`, 1))
	if _, err := Verify(changed, keys); err == nil {
		t.Error("accepted a changed counter")
	}
	changed = signed
	changed.Signature = append([]byte{}, signed.Signature...)
	changed.Signature[len(changed.Signature)-1] ^= 0xff
	if _, err := Verify(changed, keys); err == nil {
		t.Error("accepted a changed signature")
	}
	if _, err := Verify(Signed{Envelope: signed.Envelope}, keys); err == nil {
		t.Error("accepted a missing signature")
	}
	if _, err := Verify(signed, nil); err == nil {
		t.Error("accepted with no pinned keys")
	}
}

func TestRejectsForeignKey(t *testing.T) {
	signed, err := Sign(newSigner(t), envelope())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(signed, []ssh.PublicKey{newSigner(t).PublicKey()}); err == nil {
		t.Fatal("accepted a signature from a key that is not pinned")
	}
}

func TestSignatureOutsideNamespaceIsRejected(t *testing.T) {
	signer := newSigner(t)
	raw, _ := json.Marshal(envelope())
	// The same key signing the same bytes directly, as another program might.
	sig, err := signer.Sign(rand.Reader, raw)
	if err != nil {
		t.Fatal(err)
	}
	s := Signed{Envelope: raw, Signature: ssh.Marshal(sig)}
	if _, err := Verify(s, []ssh.PublicKey{signer.PublicKey()}); err == nil {
		t.Fatal("accepted a signature without the namespace")
	}
}

func TestOnlyEd25519Keys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []any{rsaKey, ecKey} {
		signer, err := ssh.NewSignerFromKey(private)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseKey(FormatKey(signer.PublicKey())); err == nil {
			t.Errorf("accepted %s", signer.PublicKey().Type())
		}
		if _, err := Sign(signer, envelope()); err == nil {
			t.Errorf("signed with %s", signer.PublicKey().Type())
		}
	}
	if _, err := ParseKey(FormatKey(newSigner(t).PublicKey())); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsUnknownEnvelopeFields(t *testing.T) {
	signer := newSigner(t)
	raw := []byte(`{"type":"pkg.install","payload":{},"device_id":"d","counter":1,"not_after":"2030-01-01T00:00:00Z","extra":1}`)
	sig, err := signer.Sign(rand.Reader, message(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(Signed{Envelope: raw, Signature: ssh.Marshal(sig)}, []ssh.PublicKey{signer.PublicKey()}); err == nil {
		t.Fatal("accepted an unknown field")
	}
}

// The ssh-agent protocol is what real use goes through, and it must produce
// the same signatures for a task far larger than an agent would accept.
func TestThroughSSHAgent(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	signers, err := keyring.Signers()
	if err != nil {
		t.Fatal(err)
	}
	env := envelope()
	env.Payload = json.RawMessage(`{"content":"` + strings.Repeat("x", 2<<20) + `"}`)
	signed, err := Sign(signers[0], env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(signed, []ssh.PublicKey{signers[0].PublicKey()}); err != nil {
		t.Fatal(err)
	}
}
