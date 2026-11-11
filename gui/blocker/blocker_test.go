package blocker

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/lang"
	"fyne.io/fyne/v2/test"

	"github.com/Two-Play/hauswart/gui/translations"
	"github.com/Two-Play/hauswart/internal/api"
)

func texts(o fyne.CanvasObject) []string {
	var found []string
	var walk func(fyne.CanvasObject)
	walk = func(o fyne.CanvasObject) {
		switch v := o.(type) {
		case *canvas.Text:
			found = append(found, v.Text)
		case *fyne.Container:
			for _, child := range v.Objects {
				walk(child)
			}
		}
	}
	walk(o)
	return found
}

func TestShowsWhatTheAgentLeft(t *testing.T) {
	if err := translations.Load(); err != nil {
		t.Fatal(err)
	}
	test.NewTempApp(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "message"), []byte("Abendessen!\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	picture := image.NewRGBA(image.Rect(0, 0, 4, 4))
	picture.Set(1, 1, color.White)
	f, _ := os.Create(filepath.Join(dir, "image"))
	png.Encode(f, picture)
	f.Close()

	message, shown := Read(dir)
	if message != "Abendessen!" || shown == nil {
		t.Fatalf("%q %v", message, shown)
	}
	if got := texts(Content(message, shown)); got[0] != "Abendessen!" || got[1] != "Hauswart" {
		t.Fatalf("got %v", got)
	}
	if got := texts(Content(Read(t.TempDir()))); got[0] != lang.L("blocker.default") {
		t.Fatalf("without a message: %v", got)
	}
}

type fakeAgent struct {
	requested []int
	loggedOut bool
}

func (f *fakeAgent) State() (api.BlockState, error) { return api.BlockState{}, nil }
func (f *fakeAgent) Request(m int) error            { f.requested = append(f.requested, m); return nil }
func (f *fakeAgent) Logout() error                  { f.loggedOut = true; return nil }

func TestScreenTimeBlockSaysWhyAndUntilWhen(t *testing.T) {
	a := test.NewTempApp(t)
	w := a.NewWindow("block")
	agent := &fakeAgent{}
	v := NewScreenView(agent, w)
	now := time.Date(2026, 11, 10, 21, 0, 0, 0, time.Local)
	v.now = func() time.Time { return now }
	w.SetContent(v.Content())
	v.Update(api.BlockState{Kind: api.BlockScreen, User: "anna", Reason: api.ScreenReasonQuota, Language: "de",
		Next: time.Date(2026, 11, 11, 15, 0, 0, 0, time.Local), LogoutAt: now.Add(7*time.Minute + 42*time.Second)})
	shown := strings.Join(texts(v.Content()), "\n")
	for _, want := range []string{"Bildschirmzeit für heute ist aufgebraucht", "Gesperrt für anna", "wieder ab morgen, 15:00", "in 7:42"} {
		if !strings.Contains(shown, want) {
			t.Errorf("missing %q in %q", want, shown)
		}
	}
	v.minutes.SetSelected("30 Minuten")
	test.Tap(v.request)
	deadline := time.Now().Add(2 * time.Second)
	for len(agent.requested) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(agent.requested) != 1 || agent.requested[0] != 30 {
		t.Fatalf("requested %v", agent.requested)
	}
	v.Update(api.BlockState{Kind: api.BlockScreen, User: "anna", Reason: api.ScreenReasonWindow, Language: "en",
		RequestedAt: now, RequestState: api.RequestDenied, LogoutAt: now.Add(time.Minute)})
	shown = strings.Join(texts(v.Content()), "\n")
	if !strings.Contains(shown, "not screen time right now") || !strings.Contains(shown, "denied") || v.request.Disabled() {
		t.Fatalf("after a denial: %q", shown)
	}
}
