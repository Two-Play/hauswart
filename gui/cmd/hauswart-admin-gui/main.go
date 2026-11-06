// hauswart-admin-gui reviews and signs tasks in a window. The keys stay in the
// ssh-agent of this computer, as with hauswart-admin.
package main

import (
	"log"

	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/lang"

	"github.com/Two-Play/hauswart/gui/admin"
	"github.com/Two-Play/hauswart/gui/translations"
	"github.com/Two-Play/hauswart/internal/admintool"
)

func main() {
	if err := translations.Load(); err != nil {
		log.Fatal(err)
	}
	a := app.NewWithID("org.hauswart.admin")
	session, err := admintool.Open()
	if err != nil {
		window := a.NewWindow(lang.L("admin.title"))
		dialog.ShowInformation(lang.L("admin.title"), lang.L("admin.notready"), window)
		window.ShowAndRun()
		return
	}
	t := admin.New(a, session)
	a.Lifecycle().SetOnStarted(t.Reload)
	t.Window().ShowAndRun()
}
