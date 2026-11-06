// Package admin is the desktop app for reviewing and signing tasks. All of the
// reviewing happens in the admintool package, which the command line tool uses too.
package admin

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/lang"
	"fyne.io/fyne/v2/widget"

	"github.com/Two-Play/hauswart/internal/admintool"
)

// Backend is what the app does with the server.
type Backend interface {
	Items() ([]admintool.Item, error)
	Sign(admintool.Item) error
	Reject(admintool.Item) error
	NameDevice(id, name string) error
	LogIn(user, password string) error
}

// App is the window.
type App struct {
	window  fyne.Window
	backend Backend
	// background runs what can take a while, such as touching a security key.
	background func(func())

	items    []admintool.Item
	selected int

	list     *widget.List
	head     *widget.Label
	body     *widget.Label
	warning  *widget.Label
	signOne  *widget.Button
	signAll  *widget.Button
	reject   *widget.Button
	nameRow  *fyne.Container
	nameText *widget.Entry
	status   *widget.Label
}

// New builds the window. Reload fills it.
func New(a fyne.App, backend Backend) *App {
	t := &App{backend: backend, selected: -1, background: func(f func()) { go f() }}
	t.window = a.NewWindow(lang.L("admin.title"))
	t.window.Resize(fyne.NewSize(900, 600))

	t.list = widget.NewList(
		func() int { return len(t.items) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i widget.ListItemID, o fyne.CanvasObject) { o.(*widget.Label).SetText(t.title(i)) },
	)
	t.list.OnSelected = t.pick

	t.head = widget.NewLabel("")
	t.head.TextStyle.Bold = true
	// A plain label on purpose: nothing from the server is ever markup here.
	t.body = widget.NewLabel("")
	t.body.Wrapping = fyne.TextWrapWord
	t.body.TextStyle.Monospace = true
	t.warning = widget.NewLabel("")
	t.warning.Wrapping = fyne.TextWrapWord
	t.warning.Importance = widget.DangerImportance

	t.signOne = widget.NewButton(lang.L("admin.sign"), t.signSelected)
	t.signOne.Importance = widget.HighImportance
	t.signAll = widget.NewButton(lang.L("admin.signall"), t.signGroup)
	t.reject = widget.NewButton(lang.L("admin.reject"), t.rejectSelected)
	t.nameText = widget.NewEntry()
	t.nameText.SetPlaceHolder(lang.L("admin.name"))
	t.nameRow = container.NewBorder(nil, nil, nil, widget.NewButton(lang.L("admin.savename"), t.saveName), t.nameText)
	t.status = widget.NewLabel("")
	t.status.Wrapping = fyne.TextWrapWord

	reload := widget.NewButton(lang.L("admin.reload"), t.Reload)
	left := container.NewBorder(widget.NewLabel(lang.L("admin.queue")), reload, nil, nil, t.list)
	actions := container.NewVBox(t.warning, t.nameRow, container.NewHBox(t.signOne, t.signAll, t.reject), t.status)
	right := container.NewBorder(t.head, actions, nil, nil, container.NewVScroll(t.body))
	split := container.NewHSplit(left, container.NewPadded(right))
	split.SetOffset(0.32)
	t.window.SetContent(split)
	t.show()
	return t
}

// Window is for showing it.
func (t *App) Window() fyne.Window { return t.window }

func (t *App) title(i int) string {
	item := t.items[i]
	name := item.DeviceName
	if name == "" {
		name = item.ServerName
	}
	return name + ": " + item.Type
}

// Reload reads the queue again. What was on the screen is gone then, so nobody
// signs on the strength of an old view.
func (t *App) Reload() {
	t.background(func() {
		items, err := t.backend.Items()
		fyne.Do(func() {
			if err != nil {
				t.failed(err)
				return
			}
			t.items = items
			t.selected = -1
			t.list.UnselectAll()
			t.list.Refresh()
			t.show()
			if len(items) > 0 {
				t.list.Select(0)
			}
		})
	})
}

func (t *App) pick(i widget.ListItemID) {
	t.selected = i
	t.status.SetText("")
	t.show()
}

func (t *App) current() (admintool.Item, bool) {
	if t.selected < 0 || t.selected >= len(t.items) {
		return admintool.Item{}, false
	}
	return t.items[t.selected], true
}

// show puts the selected task on the screen.
func (t *App) show() {
	item, ok := t.current()
	t.warning.SetText("")
	t.nameRow.Hide()
	t.signAll.Hide()
	t.signOne.Disable()
	t.reject.Disable()
	if !ok {
		t.head.SetText(lang.L("admin.pick"))
		if len(t.items) == 0 {
			t.head.SetText(lang.L("admin.empty"))
		}
		t.body.SetText("")
		return
	}
	t.reject.Enable()
	t.head.SetText(lang.L("admin.device", map[string]any{"Name": item.DeviceName}))
	var text strings.Builder
	text.WriteString(lang.L("admin.from", map[string]any{"Who": item.CreatedBy}) + "\n\n")
	if item.Problem != "" {
		if item.Unnamed {
			t.head.SetText(lang.L("admin.device", map[string]any{"Name": item.DeviceID}))
			text.WriteString(lang.L("admin.unnamed") + "\n" + lang.L("admin.servername", map[string]any{"Name": item.ServerName}))
			t.nameRow.Show()
		} else {
			text.WriteString(item.Problem)
		}
		t.body.SetText(text.String())
		return
	}
	text.WriteString(item.Text)
	if item.Changes != "" {
		text.WriteString("\n\n" + item.Changes)
	}
	// All of this stays on the screen before anyone can sign for all of them.
	if len(item.Others) > 0 {
		text.WriteString("\n\n" + lang.L("admin.others") + "\n" + strings.Join(item.Others, "\n"))
		t.signAll.Show()
	}
	t.body.SetText(text.String())
	t.warning.SetText(item.Warning)
	t.signOne.Enable()
}

func (t *App) failed(err error) {
	if strings.Contains(err.Error(), "session expired") {
		t.askLogin()
		return
	}
	t.status.SetText(err.Error())
}

func (t *App) signSelected() {
	item, ok := t.current()
	if !ok {
		return
	}
	t.work(func() error { return t.backend.Sign(item) }, lang.L("admin.signed"))
}

// signGroup signs the same policy on all devices that wait for it. A device the
// server added after the review changes the view on the way, so it is not in
// this list, and the others are signed one by one with the same checks.
func (t *App) signGroup() {
	item, ok := t.current()
	if !ok || item.Group == "" {
		return
	}
	var group []admintool.Item
	for _, other := range t.items {
		if other.Group == item.Group && other.Problem == "" {
			group = append(group, other)
		}
	}
	t.work(func() error {
		for _, each := range group {
			if err := t.backend.Sign(each); err != nil {
				return err
			}
		}
		return nil
	}, lang.L("admin.signed"))
}

func (t *App) rejectSelected() {
	item, ok := t.current()
	if !ok {
		return
	}
	t.work(func() error { return t.backend.Reject(item) }, lang.L("admin.rejected"))
}

func (t *App) saveName() {
	item, ok := t.current()
	if !ok {
		return
	}
	name := strings.TrimSpace(t.nameText.Text)
	t.work(func() error { return t.backend.NameDevice(item.DeviceID, name) }, "")
	t.nameText.SetText("")
}

// work runs an action and shows the queue as it is afterwards. The buttons are off
// meanwhile, as a second click would sign twice.
func (t *App) work(action func() error, done string) {
	t.signOne.Disable()
	t.signAll.Disable()
	t.reject.Disable()
	t.background(func() {
		err := action()
		fyne.Do(func() {
			t.signAll.Enable()
			if err != nil {
				t.show()
				t.failed(err)
				return
			}
			t.Reload()
			t.status.SetText(done)
		})
	})
}

func (t *App) askLogin() {
	user := widget.NewEntry()
	user.SetText("admin")
	password := widget.NewPasswordEntry()
	items := []*widget.FormItem{
		widget.NewFormItem(lang.L("admin.user"), user),
		widget.NewFormItem(lang.L("admin.password"), password),
	}
	dialog.ShowForm(lang.L("admin.login"), lang.L("admin.loginbutton"), lang.L("admin.cancel"), items, func(ok bool) {
		if !ok {
			return
		}
		t.background(func() {
			err := t.backend.LogIn(user.Text, password.Text)
			fyne.Do(func() {
				if err != nil {
					t.status.SetText(err.Error())
					return
				}
				t.Reload()
			})
		})
	}, t.window)
}
