// Package passkeytest is a software authenticator for tests.
package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/Two-Play/hauswart/internal/sign"
)

// Origin and RPID are what tests pin unless they say otherwise.
const (
	Origin = "https://hauswart.home.arpa:8443"
	RPID   = "hauswart.home.arpa"
)

// Authenticator holds one credential.
type Authenticator struct {
	Key          *ecdsa.PrivateKey
	CredentialID []byte
	// The fields below describe the next assertion and can be changed to
	// produce a bad one. New sets them to what a browser would send.
	Origin    string
	RPID      string
	Type      string
	Flags     byte
	ExtraJSON string
}

func New(t *testing.T) *Authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	rand.Read(id)
	return &Authenticator{Key: key, CredentialID: id, Origin: Origin, RPID: RPID, Type: "webauthn.get", Flags: 0x05}
}

// Pin is the entry a signed keys.set would put on a device.
func (a *Authenticator) Pin(t *testing.T) sign.Passkey {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&a.Key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return sign.Passkey{
		Name: "phone", CredentialID: a.CredentialID, PublicKey: der,
		RPID: RPID, Origin: Origin, NotAfter: time.Now().Add(24 * time.Hour),
	}
}

// Assert confirms an envelope the way a browser and authenticator would.
func (a *Authenticator) Assert(t *testing.T, envelope []byte) *sign.Assertion {
	t.Helper()
	return a.AssertChallenge(t, sign.PasskeyChallenge(envelope))
}

// AssertChallenge signs any challenge.
func (a *Authenticator) AssertChallenge(t *testing.T, challenge []byte) *sign.Assertion {
	t.Helper()
	client := map[string]any{
		"type":      a.Type,
		"challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"origin":    a.Origin,
	}
	if a.ExtraJSON != "" {
		if err := json.Unmarshal([]byte(a.ExtraJSON), &client); err != nil {
			t.Fatal(err)
		}
	}
	clientJSON, err := json.Marshal(client)
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte(a.RPID))
	authData := append(rpHash[:], a.Flags, 0, 0, 0, 1)
	clientHash := sha256.Sum256(clientJSON)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.Key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return &sign.Assertion{CredentialID: a.CredentialID, AuthenticatorData: authData, ClientDataJSON: clientJSON, Signature: sig}
}
