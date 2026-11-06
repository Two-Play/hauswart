// hauswart-tray is the desktop app of a family member.
package main

import (
	"log"
	"os"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"

	"github.com/Two-Play/hauswart/gui/agentclient"
	"github.com/Two-Play/hauswart/gui/translations"
	"github.com/Two-Play/hauswart/gui/tray"
)

const refreshEvery = 30 * time.Second

func main() {
	if err := translations.Load(); err != nil {
		log.Fatal(err)
	}
	a := app.NewWithID("org.hauswart.tray")
	t := tray.New(a, agentclient.New(agentclient.DefaultSocket), tray.SecretTool{})
	show := func() { fyne.Do(t.Show) }
	if !tray.Single(show) {
		return
	}
	a.Lifecycle().SetOnStarted(func() {
		t.Refresh()
		// Started from the menu, someone wants to see something. Autostart stays quiet.
		if len(os.Args) < 2 || os.Args[1] != "--background" {
			t.Show()
		}
		go func() {
			for range time.Tick(refreshEvery) {
				fyne.Do(t.Refresh)
			}
		}()
	})
	a.Run()
}
