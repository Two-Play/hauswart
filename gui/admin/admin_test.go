package admin

import (
	"errors"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2/test"

	"github.com/Two-Play/hauswart/gui/translations"
	"github.com/Two-Play/hauswart/internal/admintool"
)

type fakeBackend struct {
	items    []admintool.Item
	signed   []string
	rejected []string
	named    map[string]string
	err      error
	logins   int
	outdated string
	pins     admintool.PinState
	previews []admintool.PinChange
	pinned   []string
}

func (f *fakeBackend) Pins() (admintool.PinState, error) { return f.pins, nil }
func (f *fakeBackend) PinPreview(c admintool.PinChange) (string, error) {
	f.previews = append(f.previews, c)
	return "preview of " + c.Passkey, nil
}
func (f *fakeBackend) Pin(c admintool.PinChange, shown string) error {
	f.pinned = append(f.pinned, shown)
	return nil
}

func (f *fakeBackend) Items() ([]admintool.Item, error) { return f.items, nil }
func (f *fakeBackend) Sign(i admintool.Item) error {
	if f.err != nil {
		return f.err
	}
	f.signed = append(f.signed, i.ID)
	return nil
}
func (f *fakeBackend) Reject(i admintool.Item) error {
	f.rejected = append(f.rejected, i.ID)
	return nil
}
func (f *fakeBackend) NameDevice(id, name string) error {
	f.named[id] = name
	return nil
}
func (f *fakeBackend) Outdated() string { return f.outdated }

func (f *fakeBackend) LogIn(string, string) error {
	f.logins++
	return nil
}

func newApp(t *testing.T, items ...admintool.Item) (*App, *fakeBackend) {
	t.Helper()
	if err := translations.Load(); err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{items: items, named: map[string]string{}}
	a := New(test.NewTempApp(t), backend)
	a.background = func(f func()) { f() }
	a.Reload()
	if len(items) > 0 {
		a.list.Select(0)
	}
	return a, backend
}

func TestShowsTheFirstTask(t *testing.T) {
	a, _ := newApp(t, admintool.Item{ID: "1", DeviceName: "laptop", Text: "Install packages as root: vim", CreatedBy: "anna"})
	if !strings.Contains(a.head.Text, "laptop") || !strings.Contains(a.body.Text, "Install packages as root: vim") {
		t.Fatalf("%q %q", a.head.Text, a.body.Text)
	}
	if a.signOne.Disabled() || !a.signAll.Hidden {
		t.Fatal("wrong buttons")
	}
}

func TestSigningAndRejecting(t *testing.T) {
	a, backend := newApp(t, admintool.Item{ID: "1", DeviceName: "laptop", Text: "x"})
	test.Tap(a.signOne)
	if len(backend.signed) != 1 || backend.signed[0] != "1" {
		t.Fatalf("got %v", backend.signed)
	}
	a.list.Select(0)
	test.Tap(a.reject)
	if len(backend.rejected) != 1 {
		t.Fatalf("got %v", backend.rejected)
	}
}

func TestNothingCanBeSignedWithoutAReview(t *testing.T) {
	a, backend := newApp(t)
	if !a.signOne.Disabled() || !a.reject.Disabled() {
		t.Fatal("buttons without a task")
	}
	a.signSelected()
	if len(backend.signed) != 0 {
		t.Fatal("signed nothing at all")
	}
}

// A second click must not sign what comes next, unread.
func TestNothingIsSelectedAfterSigning(t *testing.T) {
	a, backend := newApp(t, admintool.Item{ID: "1", DeviceName: "laptop", Text: "x"}, admintool.Item{ID: "2", DeviceName: "tv", Text: "y"})
	test.Tap(a.signOne)
	test.Tap(a.signOne)
	if len(backend.signed) != 1 {
		t.Fatalf("got %v", backend.signed)
	}
	if a.status.Text == "" {
		t.Fatal("the result is not on the screen")
	}
}

func TestPickingDuringWorkChangesNothing(t *testing.T) {
	a, backend := newApp(t, admintool.Item{ID: "1", DeviceName: "laptop", Text: "x"}, admintool.Item{ID: "2", DeviceName: "tv", Text: "y"})
	var run func()
	a.background = func(f func()) { run = f }
	a.signSelected()
	a.pick(1)
	if !a.signOne.Disabled() || !a.reload.Disabled() || a.selected != 0 {
		t.Fatal("something can be started during work")
	}
	a.signSelected()
	a.background = func(f func()) { f() }
	run()
	if len(backend.signed) != 1 {
		t.Fatalf("got %v", backend.signed)
	}
}

func TestProblemsCannotBeSigned(t *testing.T) {
	a, _ := newApp(t, admintool.Item{ID: "1", Problem: "Skipped, cannot sign this", DeviceName: "laptop"})
	if !a.signOne.Disabled() || !strings.Contains(a.body.Text, "cannot sign") {
		t.Fatalf("%q", a.body.Text)
	}
}

func TestUnnamedDeviceAsksForAName(t *testing.T) {
	a, backend := newApp(t, admintool.Item{ID: "1", DeviceID: "abc", Unnamed: true, ServerName: "evil", Problem: "x"})
	if a.nameRow.Hidden || !a.signOne.Disabled() {
		t.Fatal("no way to name it")
	}
	test.Type(a.nameText, "kinder-pc")
	a.saveName()
	if backend.named["abc"] != "kinder-pc" {
		t.Fatalf("got %v", backend.named)
	}
}

// What the same policy does on the others has to be on the screen before the
// button that signs for all of them.
func TestSigningForAllShowsEveryDevice(t *testing.T) {
	one := admintool.Item{ID: "1", DeviceName: "laptop", Group: "g", Text: "policy", Changes: "Nothing changed", Others: []string{"  On kid-pc:\n    - user anna may be logged in"}}
	two := admintool.Item{ID: "2", DeviceName: "kid-pc", Group: "g", Text: "policy"}
	other := admintool.Item{ID: "3", DeviceName: "tv", Group: "h", Text: "other"}
	a, backend := newApp(t, one, two, other)
	if a.signAll.Hidden || !strings.Contains(a.body.Text, "- user anna may be logged in") {
		t.Fatalf("%q", a.body.Text)
	}
	test.Tap(a.signAll)
	if len(backend.signed) != 2 || backend.signed[1] != "2" {
		t.Fatalf("got %v", backend.signed)
	}
}

func TestWarningIsShown(t *testing.T) {
	a, _ := newApp(t, admintool.Item{ID: "1", DeviceName: "laptop", Text: "x", Warning: "WARNING: the CA"})
	if a.warning.Text != "WARNING: the CA" {
		t.Fatalf("got %q", a.warning.Text)
	}
}

func TestChangedTaskIsSaidAndNotSigned(t *testing.T) {
	a, backend := newApp(t, admintool.Item{ID: "1", DeviceName: "laptop", Text: "x"})
	backend.err = admintool.ErrChanged
	test.Tap(a.signOne)
	if !strings.Contains(a.status.Text, "changed") || len(backend.signed) != 0 {
		t.Fatalf("%q %v", a.status.Text, backend.signed)
	}
}

func TestMarkupFromTheServerStaysText(t *testing.T) {
	a, _ := newApp(t, admintool.Item{ID: "1", DeviceName: "laptop", Text: "**bold** [link](http://evil)"})
	if !strings.Contains(a.body.Text, "**bold** [link](http://evil)") {
		t.Fatalf("got %q", a.body.Text)
	}
}

func TestOtherErrorsStayVisible(t *testing.T) {
	a, backend := newApp(t, admintool.Item{ID: "1", DeviceName: "laptop", Text: "x"})
	backend.err = errors.New("none of the pinned keys is in the ssh-agent")
	test.Tap(a.signOne)
	if !strings.Contains(a.status.Text, "ssh-agent") || a.signOne.Disabled() {
		t.Fatalf("%q", a.status.Text)
	}
}

func TestPicture(t *testing.T) {
	dir := os.Getenv("HAUSWART_SHOTS")
	if dir == "" {
		t.Skip("HAUSWART_SHOTS is not set")
	}
	a, _ := newApp(t,
		admintool.Item{ID: "1", DeviceName: "kinder-pc", Type: "policy.set", CreatedBy: "admin", Group: "g",
			Text:    "SET THE POLICY of this device. It enforces this on its own, without the server:\n    forbidden package steam\n    user mia may be logged in: mon,tue 15:00-19:00",
			Changes: "  Changes since you last signed for this device:\n    + forbidden package steam",
			Others:  []string{"  On laptop:\n    You have not signed a policy for this device from here, so all of it is new."}},
		admintool.Item{ID: "2", DeviceName: "laptop", Type: "pkg.install", Text: "Install packages as root: vim"},
	)
	out, err := os.Create(filepath.Join(dir, "admin.png"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if err := png.Encode(out, a.window.Canvas().Capture()); err != nil {
		t.Fatal(err)
	}
}

func TestSigningEverythingShowsAllAndSkipsProblems(t *testing.T) {
	one := admintool.Item{ID: "1", DeviceName: "laptop", Text: "ADD Linux user anna to group games"}
	two := admintool.Item{ID: "2", DeviceName: "kid-pc", Text: "BLOCK THE SCREEN of anna", Warning: "careful"}
	broken := admintool.Item{ID: "3", DeviceName: "tv", Problem: "changed"}
	a, backend := newApp(t, one, two, broken)
	items := a.signable()
	text := everythingText(items)
	if len(items) != 2 || !strings.Contains(text, "games") || !strings.Contains(text, "BLOCK THE SCREEN") || !strings.Contains(text, "careful") {
		t.Fatalf("%d %q", len(items), text)
	}
	a.signEverything(items)
	if strings.Join(backend.signed, ",") != "1,2" {
		t.Fatalf("got %v", backend.signed)
	}
}

func TestOutdatedAppSaysSo(t *testing.T) {
	app, backend := newApp(t)
	if app.banner.Visible() {
		t.Fatal("the banner shows for an app that matches the server")
	}
	backend.outdated = "older"
	app.Reload()
	if !app.banner.Visible() {
		t.Fatal("no banner for an app that is older than the server")
	}
}

func TestLapseIsShown(t *testing.T) {
	a, _ := newApp(t, admintool.Item{ID: "1", DeviceName: "laptop", Text: "x", Lapses: time.Date(2026, 11, 12, 9, 30, 0, 0, time.Local)})
	if !strings.Contains(a.body.Text, "2026-11-12 09:30") {
		t.Fatalf("%q", a.body.Text)
	}
}
