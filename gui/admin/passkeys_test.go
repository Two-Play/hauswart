package admin

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2/test"

	"github.com/Two-Play/hauswart/internal/admintool"
)

func TestPasskeysWindowPinsAfterThePreview(t *testing.T) {
	a, backend := newApp(t)
	backend.pins = admintool.PinState{
		Passkeys: []admintool.PasskeyInfo{
			{Key: "k1", Name: "phone", Owner: "mama", Fingerprint: "SHA256:abc"},
			{Key: "k2", Name: "old", Fingerprint: "SHA256:def", Problem: "no longer on the server", PinnedOn: []string{"dev1"}},
		},
		Devices: []admintool.PinTarget{{ID: "dev1", Name: "laptop"}},
	}
	a.openPasskeys()
	p := a.passkeys
	if p == nil || len(p.devices.Options) != 1 {
		t.Fatal("no window or no devices")
	}
	if !p.pin.Disabled() {
		t.Fatal("pin is on with nothing chosen")
	}
	p.list.Select(0)
	if !strings.Contains(p.detail.Text, "SHA256:abc") {
		t.Fatalf("%q", p.detail.Text)
	}
	if !p.pin.Disabled() {
		t.Fatal("pin is on without a device")
	}
	p.devices.SetSelected(p.devices.Options)
	if p.pin.Disabled() {
		t.Fatal("pin is off")
	}
	test.Tap(p.pin)
	if len(backend.previews) != 1 || backend.previews[0].Passkey != "k1" || backend.previews[0].Devices[0] != "dev1" || backend.previews[0].Remove {
		t.Fatalf("previews %+v", backend.previews)
	}
	if len(backend.pinned) != 0 {
		t.Fatal("signed before the confirmation")
	}
	p.sign(backend.previews[0], "preview of k1")
	if len(backend.pinned) != 1 || backend.pinned[0] != "preview of k1" {
		t.Fatalf("pinned %v", backend.pinned)
	}

	// A passkey with a problem can only be removed.
	p.list.Select(1)
	p.devices.SetSelected(p.devices.Options)
	if !p.pin.Disabled() || p.remove.Disabled() {
		t.Fatal("wrong buttons for a passkey with a problem")
	}
	if !strings.Contains(p.detail.Text, "laptop") {
		t.Fatalf("%q", p.detail.Text)
	}
}
