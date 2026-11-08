// hauswart-blocker shows the full-screen notice of a blocked device.
package main

import (
	"log"

	"fyne.io/fyne/v2/app"

	"github.com/Two-Play/hauswart/gui/blocker"
	"github.com/Two-Play/hauswart/gui/translations"
)

func main() {
	if err := translations.Load(); err != nil {
		log.Fatal(err)
	}
	a := app.NewWithID("org.hauswart.blocker")
	w := a.NewWindow("Hauswart")
	// Nothing closes it from inside: the agent stops it when the block ends.
	w.SetCloseIntercept(func() {})
	w.SetFullScreen(true)
	w.SetContent(blocker.Content(blocker.Read(blocker.Dir)))
	w.ShowAndRun()
}
