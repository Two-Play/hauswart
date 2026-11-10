package admin

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/lang"
	"fyne.io/fyne/v2/widget"

	"github.com/Two-Play/hauswart/internal/admintool"
)

// passkeyWindow pins passkeys on devices. What the window shows comes from the
// server and proves nothing; the confirmation shows the fingerprint to compare.
type passkeyWindow struct {
	app    *App
	window fyne.Window

	state    admintool.PinState
	selected int
	// byLabel finds a device from its line in the check group.
	byLabel map[string]string
	busy    bool

	list    *widget.List
	detail  *widget.Label
	devices *widget.CheckGroup
	pin     *widget.Button
	remove  *widget.Button
	status  *widget.Label
}

func (t *App) openPasskeys() {
	if t.passkeys != nil {
		t.passkeys.window.RequestFocus()
		return
	}
	p := &passkeyWindow{app: t, selected: -1}
	t.passkeys = p
	p.window = fyne.CurrentApp().NewWindow(lang.L("passkeys.title"))
	p.window.Resize(fyne.NewSize(800, 500))
	p.window.SetOnClosed(func() { t.passkeys = nil })

	p.list = widget.NewList(
		func() int { return len(p.state.Passkeys) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			k := p.state.Passkeys[i]
			o.(*widget.Label).SetText(passkeyTitle(k))
		},
	)
	p.list.OnSelected = func(i widget.ListItemID) {
		if p.busy {
			return
		}
		p.selected = i
		p.status.SetText("")
		p.show()
	}
	p.detail = widget.NewLabel("")
	p.detail.Wrapping = fyne.TextWrapWord
	p.devices = widget.NewCheckGroup(nil, func([]string) { p.buttons() })
	p.pin = widget.NewButton(lang.L("passkeys.pin"), func() { p.change(false) })
	p.pin.Importance = widget.HighImportance
	p.remove = widget.NewButton(lang.L("passkeys.remove"), func() { p.change(true) })
	p.status = widget.NewLabel("")
	p.status.Wrapping = fyne.TextWrapWord

	reload := widget.NewButton(lang.L("admin.reload"), p.reload)
	left := container.NewBorder(widget.NewLabel(lang.L("passkeys.registered")), reload, nil, nil, p.list)
	devices := container.NewVBox(widget.NewLabel(lang.L("passkeys.devices")), p.devices)
	right := container.NewBorder(nil, container.NewVBox(container.NewHBox(p.pin, p.remove), p.status), nil, nil,
		container.NewVScroll(container.NewVBox(p.detail, devices)))
	split := container.NewHSplit(left, container.NewPadded(right))
	split.SetOffset(0.4)
	p.window.SetContent(split)
	p.show()
	p.window.Show()
	p.reload()
}

func passkeyTitle(k admintool.PasskeyInfo) string {
	if k.Owner == "" {
		return k.Name
	}
	return k.Name + " (" + k.Owner + ")"
}

func (p *passkeyWindow) reload() {
	p.app.background(func() {
		state, err := p.app.backend.Pins()
		fyne.Do(func() {
			if err != nil {
				p.status.SetText(err.Error())
				return
			}
			p.state = state
			p.selected = -1
			p.list.UnselectAll()
			p.list.Refresh()
			p.byLabel = map[string]string{}
			labels := make([]string, 0, len(state.Devices))
			for _, d := range state.Devices {
				label := fmt.Sprintf("%s (%s)", d.Name, shortID(d.ID))
				p.byLabel[label] = d.ID
				labels = append(labels, label)
			}
			p.devices.Options = labels
			p.devices.Selected = nil
			p.devices.Refresh()
			p.show()
		})
	})
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func (p *passkeyWindow) current() (admintool.PasskeyInfo, bool) {
	if p.selected < 0 || p.selected >= len(p.state.Passkeys) {
		return admintool.PasskeyInfo{}, false
	}
	return p.state.Passkeys[p.selected], true
}

func (p *passkeyWindow) deviceName(id string) string {
	for _, d := range p.state.Devices {
		if d.ID == id {
			return d.Name
		}
	}
	return shortID(id)
}

func (p *passkeyWindow) show() {
	k, ok := p.current()
	if !ok {
		text := lang.L("passkeys.pick")
		if len(p.state.Passkeys) == 0 {
			text = lang.L("passkeys.none")
		}
		if len(p.state.Devices) == 0 {
			text += "\n\n" + lang.L("passkeys.nodevices")
		}
		p.detail.SetText(text)
		p.buttons()
		return
	}
	var text strings.Builder
	text.WriteString(passkeyTitle(k) + "\n" + lang.L("passkeys.fingerprint", map[string]any{"Fingerprint": k.Fingerprint}) + "\n\n")
	if len(k.PinnedOn) == 0 {
		text.WriteString(lang.L("passkeys.nowhere"))
	} else {
		names := make([]string, 0, len(k.PinnedOn))
		for _, id := range k.PinnedOn {
			names = append(names, p.deviceName(id))
		}
		text.WriteString(lang.L("passkeys.pinnedon", map[string]any{"Devices": strings.Join(names, ", ")}))
	}
	if k.Problem != "" {
		text.WriteString("\n\n" + lang.L("passkeys.problem", map[string]any{"Problem": k.Problem}))
	}
	if len(p.state.Devices) == 0 {
		text.WriteString("\n\n" + lang.L("passkeys.nodevices"))
	}
	p.detail.SetText(text.String())
	p.buttons()
}

// buttons are on only for something that can be done.
func (p *passkeyWindow) buttons() {
	k, ok := p.current()
	p.pin.Disable()
	p.remove.Disable()
	if !ok || p.busy || len(p.devices.Selected) == 0 {
		return
	}
	if k.Problem == "" {
		p.pin.Enable()
	}
	p.remove.Enable()
}

func (p *passkeyWindow) chosen() []string {
	ids := make([]string, 0, len(p.devices.Selected))
	for _, label := range p.devices.Selected {
		if id, ok := p.byLabel[label]; ok {
			ids = append(ids, id)
		}
	}
	return ids
}

// change shows what would be signed, and signs exactly that after a yes.
func (p *passkeyWindow) change(remove bool) {
	k, ok := p.current()
	if !ok || p.busy {
		return
	}
	c := admintool.PinChange{Passkey: k.Key, Devices: p.chosen(), Remove: remove}
	p.setBusy(true)
	p.app.background(func() {
		text, err := p.app.backend.PinPreview(c)
		fyne.Do(func() {
			p.setBusy(false)
			if err != nil {
				p.status.SetText(err.Error())
				return
			}
			p.confirm(c, text)
		})
	})
}

func (p *passkeyWindow) confirm(c admintool.PinChange, text string) {
	body := widget.NewLabel(text)
	body.Wrapping = fyne.TextWrapWord
	body.TextStyle.Monospace = true
	scroll := container.NewVScroll(body)
	scroll.SetMinSize(fyne.NewSize(650, 350))
	title := lang.L("passkeys.confirm")
	if c.Remove {
		title = lang.L("passkeys.confirmremove")
	}
	dialog.ShowCustomConfirm(title, lang.L("admin.sign"), lang.L("admin.cancel"), scroll, func(yes bool) {
		if yes {
			p.sign(c, text)
		}
	}, p.window)
}

func (p *passkeyWindow) sign(c admintool.PinChange, text string) {
	p.setBusy(true)
	p.app.background(func() {
		err := p.app.backend.Pin(c, text)
		fyne.Do(func() {
			p.setBusy(false)
			if err != nil {
				p.status.SetText(err.Error())
				return
			}
			p.reload()
			p.status.SetText(lang.L("passkeys.signed"))
		})
	})
}

func (p *passkeyWindow) setBusy(busy bool) {
	p.busy = busy
	p.buttons()
}
