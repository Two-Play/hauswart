package tray

import (
	"testing"

	"fyne.io/fyne/v2/lang"
)

// The detail says beside it what it wants, also after the kind changed.
func TestDetailIsLabelledBesideIt(t *testing.T) {
	a, _ := newApp(t, &fakeAgent{})
	if a.detailItem.Text != lang.L("request.detail.packages") || a.detail.PlaceHolder != "" {
		t.Fatalf("%q %q", a.detailItem.Text, a.detail.PlaceHolder)
	}
	for i, kind := range kinds {
		if timed(kind) {
			a.kind.SetSelectedIndex(i)
			break
		}
	}
	if a.detailItem.Text != lang.L("request.detail.minutes") {
		t.Fatalf("%q", a.detailItem.Text)
	}
}
