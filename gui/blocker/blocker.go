// Package blocker is the full-screen notice of a blocked device. It takes no
// input: the agent runs it in a kiosk compositor on a console of its own, and
// only the agent ends it.
package blocker

import (
	"bytes"
	"image"
	"image/color"
	_ "image/jpeg" // pictures come as PNG or JPEG
	_ "image/png"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/lang"
	"fyne.io/fyne/v2/layout"
)

// Dir is where the agent puts the message and the picture.
const Dir = "/run/hauswart/block"

// Read takes the message and the picture the agent left. Either may be missing.
func Read(dir string) (string, image.Image) {
	message := ""
	if raw, err := os.ReadFile(filepath.Join(dir, "message")); err == nil {
		message = strings.TrimSpace(string(raw))
	}
	var picture image.Image
	if raw, err := os.ReadFile(filepath.Join(dir, "image")); err == nil {
		if decoded, _, err := image.Decode(bytes.NewReader(raw)); err == nil {
			picture = decoded
		}
	}
	return message, picture
}

// Content is the screen: the picture, the message, or a plain notice without one.
func Content(message string, picture image.Image) fyne.CanvasObject {
	if message == "" {
		message = lang.L("blocker.default")
	}
	background := canvas.NewRectangle(color.Black)
	text := canvas.NewText(message, color.White)
	text.TextSize = 36
	text.Alignment = fyne.TextAlignCenter
	footer := canvas.NewText("Hauswart", color.Gray{Y: 0x90})
	footer.TextSize = 14
	footer.Alignment = fyne.TextAlignCenter
	parts := []fyne.CanvasObject{layout.NewSpacer()}
	if picture != nil {
		shown := canvas.NewImageFromImage(picture)
		shown.FillMode = canvas.ImageFillContain
		shown.SetMinSize(fyne.NewSize(480, 360))
		parts = append(parts, shown)
	}
	parts = append(parts, text, layout.NewSpacer(), footer)
	return container.NewStack(background, container.NewVBox(parts...))
}
