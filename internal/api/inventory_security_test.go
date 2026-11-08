package api

import "testing"

func TestSecurityStateIsChecked(t *testing.T) {
	for _, c := range []struct {
		state SecurityState
		ok    bool
	}{
		{SecurityState{TPM: CheckOn, SecureBoot: BootLegacy, HSI: "HSI:1"}, true},
		{SecurityState{SecureBoot: CheckOn, HSI: "HSI:3!"}, true},
		{SecurityState{TPM: "maybe"}, false},
		{SecurityState{SecureBoot: "sometimes"}, false},
		{SecurityState{HSI: "HSI:2 <script>"}, false},
	} {
		inventory := Inventory{Security: c.state}
		if err := inventory.Check(); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c.state, err)
		}
	}
}
