package sign_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Two-Play/hauswart/internal/sign"
	"github.com/Two-Play/hauswart/internal/sign/passkeytest"
)

func envelopeFor(t *testing.T, device string, counter uint64) []byte {
	t.Helper()
	raw, err := json.Marshal(sign.Envelope{
		Type: "pkg.install", Payload: json.RawMessage(`{"packages":["vim"]}`),
		DeviceID: device, Counter: counter, NotAfter: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// One touch approves a fixed list. Every envelope in it verifies, each on its own.
func TestVerifyPasskeyBatch(t *testing.T) {
	a := passkeytest.New(t)
	pins := []sign.Passkey{a.Pin(t)}
	one, two := envelopeFor(t, "laptop", 1), envelopeFor(t, "tv", 7)
	batch := [][]byte{sign.EnvelopeHash(one), sign.EnvelopeHash(two)}
	assertion := a.AssertChallenge(t, sign.PasskeyBatchChallenge(batch))
	for _, raw := range [][]byte{one, two} {
		if _, _, err := sign.VerifyPasskey(sign.Signed{Envelope: raw, Passkey: assertion, Batch: batch}, pins, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVerifyPasskeyBatchRejects(t *testing.T) {
	a := passkeytest.New(t)
	pins := []sign.Passkey{a.Pin(t)}
	one, two, other := envelopeFor(t, "laptop", 1), envelopeFor(t, "tv", 7), envelopeFor(t, "laptop", 2)
	batch := [][]byte{sign.EnvelopeHash(one), sign.EnvelopeHash(two)}
	assertion := a.AssertChallenge(t, sign.PasskeyBatchChallenge(batch))
	cases := map[string]sign.Signed{
		// The server adds a task that was never in the list shown.
		"envelope not in the batch": {Envelope: other, Passkey: assertion, Batch: batch},
		// The server shows one list and sends another.
		"batch swapped": {Envelope: one, Passkey: assertion, Batch: [][]byte{sign.EnvelopeHash(one), sign.EnvelopeHash(other)}},
		"order changed": {Envelope: one, Passkey: assertion, Batch: [][]byte{sign.EnvelopeHash(two), sign.EnvelopeHash(one)}},
		"twice":         {Envelope: one, Passkey: a.AssertChallenge(t, sign.PasskeyBatchChallenge([][]byte{sign.EnvelopeHash(one), sign.EnvelopeHash(one)})), Batch: [][]byte{sign.EnvelopeHash(one), sign.EnvelopeHash(one)}},
		"one alone":     {Envelope: one, Passkey: a.AssertChallenge(t, sign.PasskeyBatchChallenge([][]byte{sign.EnvelopeHash(one)})), Batch: [][]byte{sign.EnvelopeHash(one)}},
		"empty":         {Envelope: one, Passkey: assertion, Batch: [][]byte{}},
		"short hash":    {Envelope: one, Passkey: assertion, Batch: [][]byte{sign.EnvelopeHash(one), {1, 2}}},
		// A single approval does not pass for a batch, nor the other way round.
		"single as batch": {Envelope: one, Passkey: a.Assert(t, one), Batch: batch},
		"batch as single": {Envelope: one, Passkey: assertion},
	}
	for name, signed := range cases {
		if _, _, err := sign.VerifyPasskey(signed, pins, time.Now()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	tooMany := make([][]byte, sign.MaxPasskeyBatch+1)
	tooMany[0] = sign.EnvelopeHash(one)
	for i := 1; i < len(tooMany); i++ {
		tooMany[i] = sign.EnvelopeHash(envelopeFor(t, "laptop", uint64(10+i)))
	}
	big := sign.Signed{Envelope: one, Passkey: a.AssertChallenge(t, sign.PasskeyBatchChallenge(tooMany)), Batch: tooMany}
	if _, _, err := sign.VerifyPasskey(big, pins, time.Now()); err == nil {
		t.Error("too many: accepted")
	}
}
