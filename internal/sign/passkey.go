package sign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode"
)

// passkeyNamespace separates a passkey challenge from any other use of the
// same credential. The server chooses what goes into an envelope, so a hash of
// the envelope alone could also be a valid challenge somewhere else.
const passkeyNamespace = "hauswart-task-passkey@v1\x00"

// passkeyBatchNamespace separates an approval of several envelopes from the
// approval of one, so that neither can pass for the other.
const passkeyBatchNamespace = "hauswart-task-passkey-batch@v1\x00"

// MaxPasskeyBatch caps how many tasks one touch approves.
const MaxPasskeyBatch = 10

const (
	// MaxPasskeys limits how many passkeys one device pins.
	MaxPasskeys      = 16
	maxCredentialID  = 1023
	maxPasskeyName   = 64
	authDataMinimum  = 37
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
)

// Passkey is a WebAuthn credential pinned on a device. All of it arrives in a
// signed keys.set, so the server cannot add to it or change it. The relying
// party and the origin are pinned with the key, which leaves nothing about the
// check to what the server says later.
type Passkey struct {
	Name         string `json:"name"`
	CredentialID []byte `json:"credential_id"`
	// PublicKey is DER SubjectPublicKeyInfo, as browsers report it.
	PublicKey []byte `json:"public_key"`
	RPID      string `json:"rp_id"`
	Origin    string `json:"origin"`
	// NotAfter ends the pin. Nobody can tell whether a passkey was swapped by a
	// compromised server when it was registered, so no pin lasts forever.
	NotAfter time.Time `json:"not_after"`
}

// Assertion is what an authenticator returned for one approval.
type Assertion struct {
	CredentialID      []byte `json:"credential_id"`
	AuthenticatorData []byte `json:"authenticator_data"`
	ClientDataJSON    []byte `json:"client_data_json"`
	Signature         []byte `json:"signature"`
}

// ValidPasskey checks everything about a pin that does not depend on the time.
// The admin tool, task validation and the agent all use it, so that nothing can
// be signed that the agent would refuse at its next start.
func ValidPasskey(p Passkey) error {
	if p.Name == "" || len(p.Name) > maxPasskeyName || strings.IndexFunc(p.Name, unicode.IsControl) >= 0 {
		return errors.New("invalid passkey name")
	}
	if len(p.CredentialID) == 0 || len(p.CredentialID) > maxCredentialID {
		return errors.New("invalid credential ID")
	}
	if _, err := parsePublicKey(p.PublicKey); err != nil {
		return err
	}
	if p.NotAfter.IsZero() {
		return errors.New("passkey has no expiry")
	}
	return validOrigin(p.Origin, p.RPID)
}

// validOrigin insists on one exact https origin on a DNS name. A browser would
// also accept a parent domain as relying party, but then every other host below
// it could ask for the same passkey.
func validOrigin(origin, rpID string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("origin %q is not a plain https origin", origin)
	}
	if origin != strings.ToLower(origin) {
		return fmt.Errorf("origin %q is not in lower case", origin)
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil {
		return fmt.Errorf("origin %q uses an IP address, passkeys need a DNS name", origin)
	}
	if rpID != host {
		return fmt.Errorf("relying party %q is not the host of %q", rpID, origin)
	}
	return nil
}

// parsePublicKey accepts the two algorithms a passkey may use. The key alone
// decides the algorithm: an assertion has no say in it.
func parsePublicKey(der []byte) (any, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("invalid passkey public key: %w", err)
	}
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("only P-256 is allowed for ECDSA passkeys")
		}
		return k, nil
	case ed25519.PublicKey:
		return k, nil
	}
	return nil, fmt.Errorf("passkey key type %T is not allowed", key)
}

// PasskeyFingerprint is a short form of a public key for people to compare.
func PasskeyFingerprint(p Passkey) string {
	sum := sha256.Sum256(p.PublicKey)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// PasskeyChallenge is the WebAuthn challenge for an envelope. Through it, the
// signature covers type, payload, device, counter and expiry.
func PasskeyChallenge(envelope []byte) []byte {
	h := sha256.New()
	h.Write([]byte(passkeyNamespace))
	h.Write(envelope)
	return h.Sum(nil)
}

// EnvelopeHash is how an envelope appears in a batch.
func EnvelopeHash(envelope []byte) []byte {
	sum := sha256.Sum256(envelope)
	return sum[:]
}

// PasskeyBatchChallenge is the WebAuthn challenge for several envelopes, given
// by their hashes in the order shown. Each device checks that its own envelope
// is among them, so the touch covers exactly that list and nothing else.
func PasskeyBatchChallenge(hashes [][]byte) []byte {
	h := sha256.New()
	h.Write([]byte(passkeyBatchNamespace))
	for _, hash := range hashes {
		h.Write(hash)
	}
	return h.Sum(nil)
}

// challengeFor is what the assertion of a signed task must have signed: the
// envelope alone, or a batch that holds it exactly once.
func challengeFor(s Signed) ([]byte, error) {
	if s.Batch == nil {
		return PasskeyChallenge(s.Envelope), nil
	}
	if len(s.Batch) < 2 || len(s.Batch) > MaxPasskeyBatch {
		return nil, fmt.Errorf("a batch holds 2 to %d envelopes", MaxPasskeyBatch)
	}
	own := EnvelopeHash(s.Envelope)
	found := 0
	for i, hash := range s.Batch {
		if len(hash) != sha256.Size {
			return nil, errors.New("malformed batch")
		}
		for _, before := range s.Batch[:i] {
			if bytes.Equal(before, hash) {
				return nil, errors.New("an envelope appears twice in the batch")
			}
		}
		if bytes.Equal(hash, own) {
			found++
		}
	}
	if found != 1 {
		return nil, errors.New("the batch does not hold this envelope")
	}
	return PasskeyBatchChallenge(s.Batch), nil
}

type clientData struct {
	Type        string  `json:"type"`
	Challenge   string  `json:"challenge"`
	Origin      string  `json:"origin"`
	CrossOrigin bool    `json:"crossOrigin"`
	TopOrigin   *string `json:"topOrigin"`
}

// VerifyPasskey checks an assertion against the pinned passkeys and returns the
// envelope and the passkey that approved it. As in Verify, unverified bytes
// never reach a JSON decoder: the signature comes first, and only then the
// client data and the envelope are parsed.
func VerifyPasskey(s Signed, pins []Passkey, now time.Time) (Envelope, Passkey, error) {
	a := s.Passkey
	if a == nil {
		return Envelope{}, Passkey{}, errors.New("no passkey assertion")
	}
	if len(s.Signature) != 0 {
		return Envelope{}, Passkey{}, errors.New("task carries two kinds of approval")
	}
	var pin *Passkey
	for i := range pins {
		if bytes.Equal(pins[i].CredentialID, a.CredentialID) {
			pin = &pins[i]
			break
		}
	}
	if pin == nil {
		return Envelope{}, Passkey{}, errors.New("passkey is not pinned on this device")
	}
	if !now.Before(pin.NotAfter) {
		return Envelope{}, Passkey{}, errors.New("the pin of this passkey has expired")
	}
	challenge, err := challengeFor(s)
	if err != nil {
		return Envelope{}, Passkey{}, err
	}
	if err := verifyAssertionSignature(pin.PublicKey, a); err != nil {
		return Envelope{}, Passkey{}, err
	}
	if err := checkAssertion(a, pin, challenge); err != nil {
		return Envelope{}, Passkey{}, err
	}
	var env Envelope
	dec := json.NewDecoder(bytes.NewReader(s.Envelope))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return Envelope{}, Passkey{}, fmt.Errorf("malformed envelope: %w", err)
	}
	return env, *pin, nil
}

func verifyAssertionSignature(der []byte, a *Assertion) error {
	key, err := parsePublicKey(der)
	if err != nil {
		return err
	}
	clientHash := sha256.Sum256(a.ClientDataJSON)
	signed := append(bytes.Clone(a.AuthenticatorData), clientHash[:]...)
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(signed)
		if ecdsa.VerifyASN1(k, digest[:], a.Signature) {
			return nil
		}
	case ed25519.PublicKey:
		if ed25519.Verify(k, signed, a.Signature) {
			return nil
		}
	}
	return errors.New("passkey signature does not verify")
}

func checkAssertion(a *Assertion, pin *Passkey, challenge []byte) error {
	var data clientData
	// Unknown fields stay allowed here: browsers add their own.
	if err := json.Unmarshal(a.ClientDataJSON, &data); err != nil {
		return fmt.Errorf("malformed client data: %w", err)
	}
	if data.Type != "webauthn.get" {
		return fmt.Errorf("client data has type %q", data.Type)
	}
	got, err := base64.RawURLEncoding.DecodeString(data.Challenge)
	if err != nil || !bytes.Equal(got, challenge) {
		return errors.New("assertion is for a different envelope")
	}
	if data.Origin != pin.Origin {
		return fmt.Errorf("assertion comes from origin %q", data.Origin)
	}
	if data.CrossOrigin || data.TopOrigin != nil {
		return errors.New("assertion comes from an embedded frame")
	}
	if len(a.AuthenticatorData) < authDataMinimum {
		return errors.New("authenticator data is too short")
	}
	rpHash := sha256.Sum256([]byte(pin.RPID))
	if !bytes.Equal(a.AuthenticatorData[:32], rpHash[:]) {
		return errors.New("assertion is for a different relying party")
	}
	flags := a.AuthenticatorData[32]
	if flags&flagUserPresent == 0 {
		return errors.New("authenticator did not confirm user presence")
	}
	if flags&flagUserVerified == 0 {
		return errors.New("authenticator did not verify the user")
	}
	return nil
}
