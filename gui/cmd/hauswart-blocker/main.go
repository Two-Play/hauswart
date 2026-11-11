// hauswart-blocker shows the full-screen notice of a blocked device: a block
// an admin set, or the end of someone's screen time.
package main

import (
	"log"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"

	"github.com/Two-Play/hauswart/gui/blocker"
	"github.com/Two-Play/hauswart/gui/translations"
	"github.com/Two-Play/hauswart/internal/api"
)

// refresh is how often the block asks the agent what to show.
const refresh = 2 * time.Second

func main() {
	if err := translations.Load(); err != nil {
		log.Fatal(err)
	}
	a := app.NewWithID("org.hauswart.blocker")
	w := a.NewWindow("Hauswart")
	// Nothing closes it from inside: the agent stops it when the block ends.
	w.SetCloseIntercept(func() {})
	w.SetFullScreen(true)
	agent := blocker.NewControl(blocker.ControlSocket)
	screen := blocker.NewScreenView(agent, w)
	shown, message := "", ""
	show := func() {
		state, err := agent.State()
		if err != nil {
			// An older agent, or one that is restarting: what it left in files.
			state = api.BlockState{Kind: api.BlockAccess}
		}
		fyne.Do(func() {
			switch state.Kind {
			case api.BlockScreen:
				if shown != api.BlockScreen {
					w.SetContent(screen.Content())
					shown = api.BlockScreen
				}
				screen.Update(state)
			default:
				text, picture := blocker.Read(blocker.Dir)
				if state.Message != "" {
					text = state.Message
				}
				if shown != api.BlockAccess || text != message {
					w.SetContent(blocker.Content(text, picture))
					shown, message = api.BlockAccess, text
				}
			}
		})
	}
	go func() {
		for {
			show()
			time.Sleep(refresh)
		}
	}()
	w.ShowAndRun()
}
