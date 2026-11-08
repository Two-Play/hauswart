package agent

import (
	"encoding/json"
	"testing"
)

// A device needs no TPM: the key moves into it only when its owner asks.
func TestTPMKeyIsOptIn(t *testing.T) {
	for raw, want := range map[string]bool{
		`{}`:                 false,
		`{"tpm_key": false}`: false,
		`{"tpm_key": true}`:  true,
	} {
		var c Config
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatal(err)
		}
		if got := c.wantsTPMKey(); got != want {
			t.Errorf("%s: %v", raw, got)
		}
	}
}
