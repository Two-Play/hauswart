package blocker

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/lang"
	"fyne.io/fyne/v2/test"

	"github.com/Two-Play/hauswart/gui/translations"
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
