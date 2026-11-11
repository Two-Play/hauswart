package server

import (
	"encoding/json"
	"testing"

	"github.com/Two-Play/hauswart/internal/store"
)

// The list of passkeys says where each one can approve something, from what
// the devices report.
func TestPasskeysSayWhereTheyArePinned(t *testing.T) {
	e := setup(t)
	device, agent := e.enroll()
	e.addUser("mama", "mama", store.RoleApprover)
	parent := e.login("mama")
	a := authenticator(t)
	e.register(parent, a)

	pinnedOn := func() []pinnedDevice {
		_, data := e.do(parent, "GET", "/api/passkeys", nil)
		var list []passkeyEntry
		if err := json.Unmarshal(data, &list); err != nil || len(list) != 1 {
			t.Fatalf("list %s", data)
		}
		return list[0].PinnedOn
	}
	if got := pinnedOn(); got == nil || len(got) != 0 {
		t.Fatalf("before the pin: %+v", got)
	}
	e.reportPins(agent, 0, a)
	if got := pinnedOn(); len(got) != 1 || got[0].ID != device || got[0].Hostname != "laptop" {
		t.Fatalf("after the pin: %+v", got)
	}
	// A revoked device does not count.
	if code, _ := e.do(e.login("admin"), "POST", "/api/devices/"+device+"/revoke", nil); code >= 300 {
		t.Fatalf("revoke: %d", code)
	}
	if got := pinnedOn(); len(got) != 0 {
		t.Fatalf("revoked: %+v", got)
	}
}
