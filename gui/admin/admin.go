// Package admin is the desktop app for reviewing and signing tasks. All of the
// reviewing happens in the admintool package, which the command line tool uses too.
package admin

import (
	"strings"
	"time"

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
	// Outdated is not empty when this app and the server know different
	// tasks, so that some will be skipped.
	Outdated() string
}

// App is the window.
type App struct {
	window  fyne.Window
	backend Backend
	// background runs what can take a while, such as touching a security key.
	background func(func())
	// now is the clock for "last seen", which tests set.
	now func() time.Time

	items    []admintool.Item
	selected int
	// busy says that an action runs, during which nothing else may start.
	busy bool

	list    *widget.List
	reload  *widget.Button
	head    *widget.Label
	body    *widget.Label
	warning *widget.Label
	signOne *widget.Button
	signAll *widget.Button
	// signEvery signs everything that can be signed, after showing all of it.
	signEvery *widget.Button
	reject    *widget.Button
	nameRow   *fyne.Container
	nameText  *widget.Entry
	status    *widget.Label
	// banner says that this app is older or newer than the server.
	banner *widget.Label
}

// New builds the window. Reload fills it.
func New(a fyne.App, backend Backend) *App {
	t := &App{backend: backend, selected: -1, background: func(f func()) { go f() }, now: time.Now}
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

	t.reload = widget.NewButton(lang.L("admin.reload"), t.Reload)
	t.signEvery = widget.NewButton(lang.L("admin.signevery"), t.confirmEverything)
	reload := container.NewVBox(t.signEvery, t.reload)
	left := container.NewBorder(widget.NewLabel(lang.L("admin.queue")), reload, nil, nil, t.list)
	actions := container.NewVBox(t.warning, t.nameRow, container.NewHBox(t.signOne, t.signAll, t.reject), t.status)
	right := container.NewBorder(t.head, actions, nil, nil, container.NewVScroll(t.body))
	split := container.NewHSplit(left, container.NewPadded(right))
	split.SetOffset(0.32)
	t.banner = widget.NewLabel(lang.L("admin.outdated"))
	t.banner.Wrapping = fyne.TextWrapWord
	t.banner.Importance = widget.DangerImportance
	t.banner.Hide()
	t.window.SetContent(container.NewBorder(t.banner, nil, nil, nil, split))
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
		outdated := t.backend.Outdated() != ""
		fyne.Do(func() {
			if outdated {
				t.banner.Show()
			} else {
				t.banner.Hide()
			}
			if err != nil {
				t.failed(err)
				return
			}
			t.items = items
			t.selected = -1
			t.list.UnselectAll()
			t.list.Refresh()
			// Nothing is selected on its own: the next signature takes a look and
			// a click, and a second click on Sign lands on nothing.
			t.show()
		})
	})
}

func (t *App) pick(i widget.ListItemID) {
	if t.busy {
		return
	}
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
	if !t.busy {
		t.reject.Enable()
	}
	t.head.SetText(lang.L("admin.device", map[string]any{"Name": item.DeviceName}))
	var text strings.Builder
	text.WriteString(t.context(item) + "\n\n")
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
	// What the policy does on all the others is on the screen before anyone can
	// sign for all of them. prepare lists every other device that waits for it.
	if len(item.Others) > 0 {
		text.WriteString("\n\n" + lang.L("admin.others") + "\n" + strings.Join(item.Others, "\n"))
		t.signAll.Show()
	}
	t.body.SetText(text.String())
	t.warning.SetText(item.Warning)
	if !t.busy {
		t.signOne.Enable()
		t.signAll.Enable()
	}
}

// context says when and why a task was made and what is known about its
// device. It all comes from the server and helps to decide, but proves nothing.
func (t *App) context(item admintool.Item) string {
	when := func(at time.Time) string {
		if at.IsZero() {
			return "?"
		}
		return at.Local().Format(admintool.When)
	}
	var lines []string
	if item.Automatic() {
		lines = append(lines, lang.L("admin.created.auto", map[string]any{"When": when(item.CreatedAt)}))
	} else {
		lines = append(lines, lang.L("admin.created", map[string]any{"When": when(item.CreatedAt), "Who": item.CreatedBy}))
	}
	if r := item.Request; r != nil {
		key := "admin.requested"
		if r.Reason != "" {
			key = "admin.requested.reason"
		}
		lines = append(lines, lang.L(key, map[string]any{"Who": r.User, "When": when(r.At), "Reason": r.Reason}))
	}
	device := []string{lang.L("admin.host", map[string]any{"Host": item.Hostname})}
	if item.Hostname == "" {
		device[0] = lang.L("admin.host.unknown")
	}
	if item.LastSeen.IsZero() {
		device = append(device, lang.L("admin.seen.never"))
	} else {
		n, unit := admintool.Since(item.LastSeen, t.now())
		device = append(device, lang.L("admin.seen."+unit, map[string]any{"N": n}))
	}
	if len(item.Sessions) > 0 {
		device = append(device, lang.L("admin.loggedin", map[string]any{"Who": admintool.SessionList(item.Sessions, lang.L("admin.active"))}))
	}
	return strings.Join(append(lines, strings.Join(device, " · ")), "\n")
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

// signGroup signs the same policy on the devices that were listed on the screen.
// Each goes through the checks of Sign. A device the server adds later is not in
// this list.
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

// signable is everything in the queue that can be signed.
func (t *App) signable() []admintool.Item {
	var items []admintool.Item
	for _, item := range t.items {
		if item.Problem == "" {
			items = append(items, item)
		}
	}
	return items
}

// everythingText is what the confirmation shows: each task in full, so that
// nothing is signed that was not on the screen.
func everythingText(items []admintool.Item) string {
	var text strings.Builder
	for i, item := range items {
		if i > 0 {
			text.WriteString("\n\n")
		}
		text.WriteString(lang.L("admin.device", map[string]any{"Name": item.DeviceName}) + "\n" + item.Text)
		if item.Changes != "" {
			text.WriteString("\n" + item.Changes)
		}
		if item.Warning != "" {
			text.WriteString("\n" + item.Warning)
		}
	}
	return text.String()
}

func (t *App) confirmEverything() {
	items := t.signable()
	if len(items) == 0 {
		return
	}
	body := widget.NewLabel(everythingText(items))
	body.Wrapping = fyne.TextWrapWord
	body.TextStyle.Monospace = true
	scroll := container.NewVScroll(body)
	scroll.SetMinSize(fyne.NewSize(700, 400))
	dialog.ShowCustomConfirm(lang.L("admin.signevery.title", map[string]any{"Count": len(items)}),
		lang.L("admin.sign"), lang.L("admin.cancel"), scroll,
		func(yes bool) {
			if yes {
				t.signEverything(items)
			}
		}, t.window)
}

// signEverything signs what the confirmation showed. Each goes through the
// checks of Sign, and a task the server adds meanwhile is not among them.
func (t *App) signEverything(items []admintool.Item) {
	t.work(func() error {
		for _, each := range items {
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

// work runs an action and shows the queue as it is afterwards. Everything else is
// off meanwhile, including picking another task: a touch of a security key can take
// a while, and a second click would sign twice.
func (t *App) work(action func() error, done string) {
	if t.busy {
		return
	}
	t.busy = true
	t.signOne.Disable()
	t.signAll.Disable()
	t.reject.Disable()
	t.reload.Disable()
	t.background(func() {
		err := action()
		fyne.Do(func() {
			t.busy = false
			t.reload.Enable()
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
		name, secret := user.Text, password.Text
		t.background(func() {
			err := t.backend.LogIn(name, secret)
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
