package tray

import (
	"errors"
	"image/png"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/lang"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/Two-Play/hauswart/gui/agentclient"
	"github.com/Two-Play/hauswart/gui/translations"
	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/catalog"
)

type fakeAgent struct {
	status   api.UserStatus
	err      error
	sent     []api.UserRequest
	refuse   error
	approved bool
	searched []string
	found    []catalog.Entry
}

func (f *fakeAgent) Status() (api.UserStatus, error) { return f.status, f.err }

func (f *fakeAgent) Search(kind, q string) ([]catalog.Entry, error) {
	f.searched = append(f.searched, kind+" "+q)
	return f.found, nil
}

func (f *fakeAgent) Request(r api.UserRequest) (string, error) {
	f.sent = append(f.sent, r)
	if f.approved {
		return api.RequestApproved, f.refuse
	}
	return api.RequestOpen, f.refuse
}

type fakeKeyring struct {
	stored []string
	err    error
}

func (f *fakeKeyring) StoreNextcloud(p string) error {
	f.stored = append(f.stored, p)
	return f.err
}

var noon = time.Date(2026, 11, 9, 12, 0, 0, 0, time.Local)

func newApp(t *testing.T, agent *fakeAgent) (*App, *fakeKeyring) {
	t.Helper()
	if err := translations.Load(); err != nil {
		t.Fatal(err)
	}
	a := test.NewTempApp(t)
	keyring := &fakeKeyring{}
	app := New(a, agent, keyring)
	app.now = func() time.Time { return noon }
	app.background = func(f func()) { f() }
	app.later = func(_ time.Duration, f func()) *time.Timer {
		f()
		return nil
	}
	return app, keyring
}

func TestShowsWhatIsLeft(t *testing.T) {
	agent := &fakeAgent{status: api.UserStatus{User: "mia", ScreenTime: &api.ScreenStatus{Allowed: true, Until: noon.Add(90 * time.Minute)}}}
	app, _ := newApp(t, agent)
	app.Refresh()
	if !strings.Contains(app.screen.Text, "1 h 30 min") || !strings.Contains(app.screen.Text, "13:30") {
		t.Fatalf("got %q", app.screen.Text)
	}
	if app.menuTime.Label != app.screen.Text {
		t.Fatalf("the tray says %q", app.menuTime.Label)
	}
}

func TestOtherStates(t *testing.T) {
	agent := &fakeAgent{}
	app, _ := newApp(t, agent)
	app.Refresh()
	if app.screen.Text != lang.L("screen.free") {
		t.Fatalf("got %q", app.screen.Text)
	}
	agent.status.ScreenTime = &api.ScreenStatus{}
	app.Refresh()
	if app.screen.Text != lang.L("screen.over") {
		t.Fatalf("got %q", app.screen.Text)
	}
	agent.err = errors.New("no agent")
	app.Refresh()
	if app.screen.Text != lang.L("unreachable") {
		t.Fatalf("got %q", app.screen.Text)
	}
}

func TestDurations(t *testing.T) {
	for d, want := range map[time.Duration]string{
		30 * time.Second: "1 min",
		59 * time.Minute: "59 min",
		60 * time.Minute: "1 h 0 min",
		61 * time.Minute: "1 h 1 min",
	} {
		if got := duration(d); got != want {
			t.Errorf("%s: got %q", d, got)
		}
	}
}

func TestSharesAndNotice(t *testing.T) {
	agent := &fakeAgent{status: api.UserStatus{Shares: []string{"Family", "Music"}, PolicyIssues: true}}
	app, _ := newApp(t, agent)
	app.Refresh()
	if app.shares.Text != "Family\nMusic" || app.notice.Text == "" {
		t.Fatalf("%q %q", app.shares.Text, app.notice.Text)
	}
	agent.status = api.UserStatus{}
	app.Refresh()
	if app.shares.Text != lang.L("shares.none") || app.notice.Text != "" {
		t.Fatalf("%q %q", app.shares.Text, app.notice.Text)
	}
}

func TestAsking(t *testing.T) {
	agent := &fakeAgent{}
	app, _ := newApp(t, agent)
	app.ShowRequest(api.RequestScreen)
	test.Type(app.detail, "30")
	test.Type(app.reason, "homework")
	app.send()
	if len(agent.sent) != 1 || agent.sent[0] != (api.UserRequest{Kind: api.RequestScreen, Detail: "30", Reason: "homework"}) {
		t.Fatalf("got %+v", agent.sent)
	}
	if app.result.Text != lang.L("request.sent") || app.detail.Text != "" {
		t.Fatalf("%q %q", app.result.Text, app.detail.Text)
	}
}

func TestRefusalsAreSaidInPlainWords(t *testing.T) {
	agent := &fakeAgent{}
	app, _ := newApp(t, agent)
	for err, want := range map[error]string{
		agentclient.ErrTooMany:     lang.L("request.toomany"),
		agentclient.ErrUnreachable: lang.L("request.offline"),
	} {
		agent.refuse = err
		test.Type(app.detail, "vim")
		app.send()
		if app.result.Text != want {
			t.Errorf("got %q", app.result.Text)
		}
		if app.detail.Text == "" {
			t.Error("the text was lost")
		}
		app.detail.SetText("")
	}
}

func TestRefusalsOfTheServerSayWhy(t *testing.T) {
	agent := &fakeAgent{}
	app, _ := newApp(t, agent)
	agent.refuse = agentclient.Refused{Code: api.ErrNoSuchUser}
	test.Type(app.detail, "vim")
	app.send()
	if app.result.Text != lang.L("request.refused.no_such_user") {
		t.Fatalf("got %q", app.result.Text)
	}
}

func TestAutomaticApprovalIsSaid(t *testing.T) {
	agent := &fakeAgent{approved: true}
	app, _ := newApp(t, agent)
	test.Type(app.detail, "vim")
	app.send()
	if app.result.Text != lang.L("request.approved") || app.detail.Text != "" {
		t.Fatalf("%q %q", app.result.Text, app.detail.Text)
	}
}

func TestNamesAreSuggestedWhileTyping(t *testing.T) {
	agent := &fakeAgent{found: []catalog.Entry{{Name: "org.gimp.GIMP"}, {Name: "gimp"}}}
	app, _ := newApp(t, agent)
	app.kind.SetSelectedIndex(1) // flatpak
	app.detail.SetText("vim gim")
	if len(agent.searched) != 1 || agent.searched[0] != "flatpak gim" {
		t.Fatalf("searched %v", agent.searched)
	}
	if got := app.options; len(got) != 2 || got[0] != "vim org.gimp.GIMP" {
		t.Fatalf("options %v", got)
	}
	if len(app.suggestions.Objects) != 2 {
		t.Fatalf("%d suggestions shown", len(app.suggestions.Objects))
	}
	test.Tap(app.suggestions.Objects[0].(*widget.Button))
	if app.detail.Text != "vim org.gimp.GIMP " || len(app.suggestions.Objects) != 0 {
		t.Fatalf("picked %q, %d left", app.detail.Text, len(app.suggestions.Objects))
	}
	app.detail.SetText("g")
	app.ShowRequest(api.RequestScreen)
	app.detail.SetText("30")
	if len(agent.searched) != 1 || len(app.options) != 0 {
		t.Fatalf("searched %v, options %v", agent.searched, app.options)
	}
}

func TestBlockedKindIsSaid(t *testing.T) {
	agent := &fakeAgent{refuse: agentclient.Refused{Code: api.ErrRequestBlocked}}
	app, _ := newApp(t, agent)
	test.Type(app.detail, "vim")
	app.send()
	if app.result.Text != lang.L("request.refused.request_blocked") {
		t.Fatalf("got %q", app.result.Text)
	}
}

func TestMinutesAreCheckedBeforeSending(t *testing.T) {
	agent := &fakeAgent{}
	app, _ := newApp(t, agent)
	app.ShowRequest(api.RequestScreen)
	test.Type(app.detail, "abc")
	app.send()
	if len(agent.sent) != 0 || app.result.Text != lang.L("request.badminutes") {
		t.Fatalf("%v %q", agent.sent, app.result.Text)
	}
}

func TestNextcloudOnlyWithARule(t *testing.T) {
	agent := &fakeAgent{}
	app, keyring := newApp(t, agent)
	app.Refresh()
	if slices.Contains(app.tabs.Items, app.cloud) {
		t.Fatal("the tab is there without a rule")
	}
	agent.status.Nextcloud = &api.NextcloudRule{URL: "https://cloud.home", Mode: api.NextcloudDrive}
	app.Refresh()
	app.Refresh()
	if count := len(app.tabs.Items); count != 3 {
		t.Fatalf("got %d tabs", count)
	}
	test.Type(app.password, "app-password")
	app.saveNextcloud()
	if !slices.Equal(keyring.stored, []string{"app-password"}) || app.password.Text != "" {
		t.Fatalf("%v %q", keyring.stored, app.password.Text)
	}
	agent.status.Nextcloud.Mode = api.NextcloudClient
	app.Refresh()
	if app.password.Visible() {
		t.Fatal("the client needs no password here")
	}
	agent.status.Nextcloud = nil
	app.Refresh()
	if len(app.tabs.Items) != 2 {
		t.Fatal("the tab stayed")
	}
}

func TestClosingOnlyHides(t *testing.T) {
	app, _ := newApp(t, &fakeAgent{})
	app.Show()
	app.window.Close()
	if len(fyne.CurrentApp().Driver().AllWindows()) == 0 {
		t.Fatal("closing the window ended it")
	}
}

// Writes what the app looks like, for a look by a person.
func TestPicture(t *testing.T) {
	dir := os.Getenv("HAUSWART_SHOTS")
	if dir == "" {
		t.Skip("HAUSWART_SHOTS is not set")
	}
	agent := &fakeAgent{status: api.UserStatus{
		ScreenTime: &api.ScreenStatus{Allowed: true, Until: noon.Add(95 * time.Minute)},
		Shares:     []string{"Family"},
		Nextcloud:  &api.NextcloudRule{URL: "https://cloud.home", Mode: api.NextcloudDrive},
	}}
	app, _ := newApp(t, agent)
	app.Refresh()
	for i, item := range app.tabs.Items {
		app.tabs.Select(item)
		out, err := os.Create(filepath.Join(dir, "tray-"+string(rune('0'+i))+".png"))
		if err != nil {
			t.Fatal(err)
		}
		if err := png.Encode(out, app.window.Canvas().Capture()); err != nil {
			t.Fatal(err)
		}
		out.Close()
	}
}
