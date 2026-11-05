// Package sign protects tasks against a compromised server. An admin signs
// tasks with an SSH key on their own computer, and a device executes only what
// verifies against the keys pinned on it, which the server cannot change.
package sign

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// namespace separates these signatures from any other use of the same key,
// such as logging in over SSH.
const namespace = "hauswart-task@v1"

// Envelope is what gets signed. The device ID binds it to one device, and the
// counter to one place in that device's sequence.
type Envelope struct {
	Type     string          `json:"type"`
	Payload  json.RawMessage `json:"payload"`
	DeviceID string          `json:"device_id"`
	Counter  uint64          `json:"counter"`
	NotAfter time.Time       `json:"not_after"`
	// Freshness holds a value the device made up recently. Only passkey
	// approvals use it: the server chooses their expiry, so this is what ties
	// an approval to the time it was given.
	Freshness string `json:"freshness,omitempty"`
}

// Signed travels through the server, which can read it but not change it.
type Signed struct {
	Envelope  []byte `json:"envelope"`
	Signature []byte `json:"signature"`
	// Passkey replaces Signature on a task approved in a browser, which is
	// weaker and limited by the device. See VerifyPasskey.
	Passkey *Assertion `json:"passkey,omitempty"`
}

// Only Ed25519 keys are accepted: one algorithm without hash choices, in a
// software and a FIDO variant.
var allowedFormats = map[string]bool{
	ssh.KeyAlgoED25519:   true,
	ssh.KeyAlgoSKED25519: true,
}

// ParseKey reads a public key in authorized_keys format.
func ParseKey(line string) (ssh.PublicKey, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	if !allowedFormats[key.Type()] {
		return nil, fmt.Errorf("key type %s is not allowed, use ed25519 or ed25519-sk", key.Type())
	}
	return key, nil
}

// FormatKey is the reverse of ParseKey, without a comment.
func FormatKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// message follows the SSHSIG layout: it signs a hash, which keeps large tasks
// within what an ssh-agent accepts, under a namespace.
func message(envelope []byte) []byte {
	digest := sha512.Sum512(envelope)
	body := ssh.Marshal(struct {
		Namespace string
		Reserved  string
		Hash      string
		Digest    string
	}{namespace, "", "sha512", string(digest[:])})
	return append([]byte("SSHSIG"), body...)
}

// Sign signs an envelope. The signer usually comes from an ssh-agent.
func Sign(signer ssh.Signer, env Envelope) (Signed, error) {
	if !allowedFormats[signer.PublicKey().Type()] {
		return Signed{}, fmt.Errorf("key type %s is not allowed", signer.PublicKey().Type())
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return Signed{}, err
	}
	sig, err := signer.Sign(rand.Reader, message(raw))
	if err != nil {
		return Signed{}, err
	}
	return Signed{Envelope: raw, Signature: ssh.Marshal(sig)}, nil
}

// Verify checks a signature against the pinned keys and only then parses the
// envelope, so unverified bytes never reach the JSON decoder.
func Verify(s Signed, keys []ssh.PublicKey) (Envelope, error) {
	if s.Passkey != nil {
		return Envelope{}, errors.New("task carries a passkey assertion")
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(s.Signature, &sig); err != nil {
		return Envelope{}, fmt.Errorf("malformed signature: %w", err)
	}
	if !allowedFormats[sig.Format] {
		return Envelope{}, fmt.Errorf("signature format %q is not allowed", sig.Format)
	}
	msg := message(s.Envelope)
	for _, key := range keys {
		if key.Type() != sig.Format || key.Verify(msg, &sig) != nil {
			continue
		}
		var env Envelope
		dec := json.NewDecoder(bytes.NewReader(s.Envelope))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&env); err != nil {
			return Envelope{}, fmt.Errorf("malformed envelope: %w", err)
		}
		return env, nil
	}
	return Envelope{}, errors.New("signature does not match a pinned key")
}
