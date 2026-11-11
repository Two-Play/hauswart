// Package tray is the desktop app of a member: how much screen time is
// left, what is connected, and a way to ask for something.
package tray

import (
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/lang"
	"fyne.io/fyne/v2/widget"

	"github.com/Two-Play/hauswart/gui/agentclient"
	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/catalog"
)

// Agent is what the app needs from the agent on this device.
type Agent interface {
	Status() (api.UserStatus, error)
	Request(api.UserRequest) (string, error)
	Search(kind, q string) ([]catalog.Entry, error)
	History() (api.History, error)
}

// searchDelay waits for a pause in typing before asking.
const searchDelay = 300 * time.Millisecond

// maxSuggestions keeps the window small.
const maxSuggestions = 6

// Keyring keeps the Nextcloud password of the person running this.
type Keyring interface {
	StoreNextcloud(password string) error
}

//go:embed hauswart.svg
var iconData []byte

var icon = fyne.NewStaticResource("hauswart.svg", iconData)

// kinds are the requests the form offers, in its order.
var kinds = []string{"software", "flatpak", api.RequestScreen, "sudo"}

// App is the window and the tray menu.
type App struct {
	app     fyne.App
	window  fyne.Window
	agent   Agent
	keyring Keyring
	now     func() time.Time
	// background keeps waiting for the agent away from the window.
	background func(func())
	// later runs a search after a pause in typing. Tests run it at once.
	later func(time.Duration, func()) *time.Timer
	// searches counts searches, so that a late answer does not win.
	searches int
	timer    *time.Timer
	// options are what the name field offers now, as the whole text with the
	// last word completed, and suggestions shows them as buttons.
	options     []string
	suggestions *fyne.Container

	status api.UserStatus
	// lines are the history, newest first.
	lines []historyLine

	screen  *widget.Label
	shares  *widget.Label
	notice  *widget.Label
	tabs    *container.AppTabs
	request *container.TabItem
	cloud   *container.TabItem
	history *widget.List
	empty   *widget.Label
	kind    *widget.Select
	detail  *widget.Entry
	// detailItem labels the detail beside it, as a placeholder is gone once
	// something is typed and hard to see when the kind changes.
	detailItem *widget.FormItem
	detailForm *widget.Form
	reason     *widget.Entry
	result     *widget.Label
	// sendButton is off while the device is suspended.
	sendButton *widget.Button
	cloudURL   *widget.Label
	cloudTip   *widget.Label
	password   *widget.Entry
	saveKey    *widget.Button
	saved      *widget.Label
	menuTime   *fyne.MenuItem
	menu       *fyne.Menu
}

// New builds the app. Refresh fills it.
func New(a fyne.App, agent Agent, keyring Keyring) *App {
	t := &App{app: a, agent: agent, keyring: keyring, now: time.Now, background: func(f func()) { go f() }, later: time.AfterFunc}
	t.window = a.NewWindow(lang.L("title"))
	t.window.Resize(fyne.NewSize(420, 380))
	// The window comes and goes, the app stays in the tray.
	t.window.SetCloseIntercept(t.window.Hide)

	t.screen = widget.NewLabel("")
	t.screen.TextStyle.Bold = true
	t.shares = widget.NewLabel("")
	t.notice = widget.NewLabel("")
	t.notice.Wrapping = fyne.TextWrapWord
	dashboard := widget.NewButton(lang.L("menu.dashboard"), t.openDashboard)
	status := container.NewVBox(t.screen, widget.NewSeparator(), widget.NewLabel(lang.L("shares")), t.shares, t.notice, dashboard)

	t.tabs = container.NewAppTabs(container.NewTabItem(lang.L("tab.status"), container.NewPadded(status)))
	t.request = container.NewTabItem(lang.L("tab.request"), container.NewPadded(t.requestForm()))
	t.tabs.Append(t.request)
	t.tabs.Append(container.NewTabItem(lang.L("tab.history"), container.NewPadded(t.historyView())))
	t.cloud = container.NewTabItem(lang.L("tab.nextcloud"), container.NewPadded(t.cloudForm()))
	t.window.SetContent(t.tabs)

	t.menuTime = fyne.NewMenuItem("", t.Show)
	t.menuTime.Disabled = true
	t.menu = fyne.NewMenu(lang.L("title"),
		t.menuTime,
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem(lang.L("menu.open"), t.Show),
		fyne.NewMenuItem(lang.L("menu.request"), func() { t.ShowRequest("software") }),
		fyne.NewMenuItem(lang.L("menu.time"), func() { t.ShowRequest(api.RequestScreen) }),
		fyne.NewMenuItem(lang.L("menu.dashboard"), t.openDashboard),
	)
	a.SetIcon(icon)
	if tray, ok := a.(desktop.App); ok {
		tray.SetSystemTrayMenu(t.menu)
		tray.SetSystemTrayIcon(icon)
		tray.SetSystemTrayWindow(t.window)
	}
	return t
}

func (t *App) requestForm() fyne.CanvasObject {
	labels := make([]string, len(kinds))
	for i, kind := range kinds {
		labels[i] = lang.L("request.kind." + kind)
	}
	t.detail = widget.NewEntry()
	t.detail.OnChanged = t.suggest
	// A list that is always in view: the drop-down of a select entry only
	// opens on a click, so nobody would see the suggestions while typing.
	t.suggestions = container.NewVBox()
	t.reason = widget.NewEntry()
	t.result = widget.NewLabel("")
	t.result.Wrapping = fyne.TextWrapWord
	t.detailItem = widget.NewFormItem("", container.NewVBox(t.detail, t.suggestions))
	t.kind = widget.NewSelect(labels, func(string) { t.showDetailHint() })
	form := widget.NewForm(
		widget.NewFormItem(lang.L("request.kind"), t.kind),
		t.detailItem,
		widget.NewFormItem(lang.L("request.reason"), t.reason),
	)
	t.detailForm = form
	t.kind.SetSelectedIndex(0)
	t.sendButton = widget.NewButton(lang.L("request.send"), t.send)
	return container.NewVBox(form, t.sendButton, t.result)
}

// suggest offers names for the word being typed. The options are the whole
// text, with the last word completed, as choosing one replaces the text.
func (t *App) suggest(text string) {
	kind := t.selectedKind()
	if t.timer != nil {
		t.timer.Stop()
	}
	t.searches++
	ticket := t.searches
	words := strings.Fields(text)
	if timed(kind) || len(words) == 0 || strings.HasSuffix(text, " ") || len(words[len(words)-1]) < catalog.MinQuery {
		t.setOptions(nil, nil)
		return
	}
	search := api.SearchPackage
	if kind == api.RequestFlatpak {
		search = api.SearchFlatpak
	}
	prefix, last := words[:len(words)-1], words[len(words)-1]
	t.timer = t.later(searchDelay, func() {
		t.background(func() {
			entries, err := t.agent.Search(search, last)
			fyne.Do(func() {
				if ticket != t.searches {
					return
				}
				var options, labels []string
				for _, entry := range entries {
					if err != nil || entry.Name == last || len(options) == maxSuggestions {
						continue
					}
					options = append(options, strings.Join(append(slices.Clone(prefix), entry.Name), " "))
					label := entry.Name
					if entry.Title != "" {
						label = entry.Title + " (" + entry.Name + ")"
					}
					labels = append(labels, label)
				}
				t.setOptions(options, labels)
			})
		})
	})
}

func (t *App) setOptions(options, labels []string) {
	t.options = options
	t.suggestions.RemoveAll()
	for i, option := range options {
		button := widget.NewButton(labels[i], func() { t.pick(option) })
		button.Alignment = widget.ButtonAlignLeading
		button.Importance = widget.LowImportance
		t.suggestions.Add(button)
	}
	t.suggestions.Refresh()
}

// pick takes a suggestion. The text then holds a whole name, which needs no
// more suggestions.
func (t *App) pick(option string) {
	t.detail.SetText(option + " ")
	t.setOptions(nil, nil)
	t.window.Canvas().Focus(t.detail)
}

func (t *App) selectedKind() string {
	if i := t.kind.SelectedIndex(); i >= 0 {
		return kinds[i]
	}
	return kinds[0]
}

func timed(kind string) bool { return kind == "sudo" || kind == api.RequestScreen }

func (t *App) showDetailHint() {
	if t.detailItem == nil || t.detailForm == nil {
		return
	}
	if timed(t.selectedKind()) {
		t.detailItem.Text = lang.L("request.detail.minutes")
	} else {
		t.detailItem.Text = lang.L("request.detail.packages")
	}
	t.detailForm.Refresh()
}

func (t *App) send() {
	request := api.UserRequest{
		Kind:   t.selectedKind(),
		Detail: strings.TrimSpace(t.detail.Text),
		Reason: strings.TrimSpace(t.reason.Text),
	}
	if timed(request.Kind) {
		if minutes, err := strconv.Atoi(request.Detail); err != nil || minutes < 1 {
			t.result.SetText(lang.L("request.badminutes"))
			return
		}
	}
	t.background(func() {
		status, err := t.agent.Request(request)
		fyne.Do(func() { t.sent(status, err) })
	})
}

func (t *App) sent(status string, err error) {
	var refused agentclient.Refused
	switch {
	case err == nil && status == api.RequestApproved:
		t.result.SetText(lang.L("request.approved"))
		t.detail.SetText("")
		t.reason.SetText("")
	case err == nil:
		t.result.SetText(lang.L("request.sent"))
		t.detail.SetText("")
		t.reason.SetText("")
	case errors.Is(err, agentclient.ErrTooMany):
		t.result.SetText(lang.L("request.toomany"))
	case errors.Is(err, agentclient.ErrUnreachable):
		t.result.SetText(lang.L("request.offline"))
	case errors.As(err, &refused):
		t.result.SetText(lang.L("request.refused." + refused.Code))
	default:
		t.result.SetText(lang.L("request.failed", map[string]any{"Reason": err.Error()}))
	}
}

func (t *App) cloudForm() fyne.CanvasObject {
	t.cloudURL = widget.NewLabel("")
	t.cloudTip = widget.NewLabel("")
	t.cloudTip.Wrapping = fyne.TextWrapWord
	t.password = widget.NewPasswordEntry()
	t.saveKey = widget.NewButton(lang.L("nextcloud.save"), t.saveNextcloud)
	t.saved = widget.NewLabel("")
	t.saved.Wrapping = fyne.TextWrapWord
	password := widget.NewForm(widget.NewFormItem(lang.L("nextcloud.password"), t.password))
	return container.NewVBox(t.cloudURL, t.cloudTip, password, t.saveKey, t.saved)
}

func (t *App) saveNextcloud() {
	secret := strings.TrimSpace(t.password.Text)
	if secret == "" {
		return
	}
	t.background(func() {
		err := t.keyring.StoreNextcloud(secret)
		fyne.Do(func() {
			if err != nil {
				t.saved.SetText(lang.L("nextcloud.failed", map[string]any{"Reason": err.Error()}))
				return
			}
			t.password.SetText("")
			t.saved.SetText(lang.L("nextcloud.saved"))
		})
	})
}

func (t *App) openDashboard() {
	if t.status.Dashboard == "" {
		return
	}
	if target, err := url.Parse(t.status.Dashboard); err == nil {
		t.app.OpenURL(target)
	}
}

// Show opens the window.
func (t *App) Show() {
	t.window.Show()
	t.window.RequestFocus()
}

// ShowRequest opens the form for one kind of request.
func (t *App) ShowRequest(kind string) {
	for i, known := range kinds {
		if known == kind {
			t.kind.SetSelectedIndex(i)
		}
	}
	t.tabs.Select(t.request)
	t.Show()
}

// duration says a time span the way people do, in minutes up to an hour.
func duration(d time.Duration) string {
	minutes := int((d + time.Minute - 1) / time.Minute)
	if minutes < 60 {
		return fmt.Sprintf("%d min", minutes)
	}
	return fmt.Sprintf("%d h %d min", minutes/60, minutes%60)
}

func (t *App) screenText() string {
	s := t.status.ScreenTime
	switch {
	case s == nil:
		return lang.L("screen.free")
	case !s.Allowed:
		return lang.L("screen.over")
	}
	return lang.L("screen.left", map[string]any{
		"Time":  duration(s.Until.Sub(t.now())),
		"Until": s.Until.Local().Format("15:04"),
	})
}

// Refresh asks the agent and shows the answer.
func (t *App) Refresh() {
	t.background(func() {
		status, err := t.agent.Status()
		fyne.Do(func() { t.show(status, err) })
		history, err := t.agent.History()
		fyne.Do(func() { t.showHistory(history, err) })
	})
}

func (t *App) show(status api.UserStatus, err error) {
	if err != nil {
		t.screen.SetText(lang.L("unreachable"))
		t.setMenuTime(lang.L("unreachable"))
		return
	}
	t.status = status
	text := t.screenText()
	t.screen.SetText(text)
	t.setMenuTime(text)
	if live := status.Terminal; live != nil {
		// Live access goes first in the menu, where it shows without opening
		// the window.
		t.setMenuTime(terminalText(live))
	}

	t.shares.SetText(lang.L("shares.none"))
	if len(status.Shares) > 0 {
		t.shares.SetText(strings.Join(status.Shares, "\n"))
	}
	t.notice.SetText("")
	if status.PolicyIssues {
		t.notice.SetText(lang.L("policy.issues"))
	}
	if a := status.Access; a != nil {
		until := lang.L("access.lasting")
		if !a.Until.IsZero() {
			until = t.clock(a.Until)
		}
		t.notice.SetText(lang.L("access."+a.Mode, map[string]any{"Until": until}))
	}
	if live := status.Terminal; live != nil {
		t.notice.SetText(terminalText(live))
	}
	if status.Suspended {
		t.notice.SetText(lang.L("suspended"))
		t.sendButton.Disable()
		t.result.SetText(lang.L("suspended"))
	} else if t.sendButton.Disabled() {
		t.sendButton.Enable()
		t.result.SetText("")
	}
	t.showCloud(status.Nextcloud)
}

// terminalText says that an admin works on the device right now, as whom and
// approved by whom.
func terminalText(live *api.TerminalStatus) string {
	return lang.L("terminal.live", map[string]any{
		"User": live.User, "Approver": live.Approver,
		"Since": live.Since.Local().Format("15:04"), "Until": live.Until.Local().Format("15:04"),
	})
}

func (t *App) setMenuTime(text string) {
	if t.menuTime.Label == text {
		return
	}
	t.menuTime.Label = text
	t.menu.Refresh()
}

func (t *App) showCloud(rule *api.NextcloudRule) {
	present := false
	for _, item := range t.tabs.Items {
		present = present || item == t.cloud
	}
	if rule == nil {
		if present {
			t.tabs.Remove(t.cloud)
		}
		return
	}
	if !present {
		t.tabs.Append(t.cloud)
	}
	t.cloudURL.SetText(lang.L("nextcloud.url", map[string]any{"URL": rule.URL}))
	drive := rule.Mode == api.NextcloudDrive
	t.cloudTip.SetText(lang.L("nextcloud." + rule.Mode))
	if drive {
		t.password.Show()
		t.saveKey.Show()
	} else {
		t.password.Hide()
		t.saveKey.Hide()
	}
}

// historyLine is one entry of the history: a request or a change.
type historyLine struct {
	at   time.Time
	text string
}

func (t *App) historyView() fyne.CanvasObject {
	t.empty = widget.NewLabel(lang.L("history.none"))
	t.empty.Wrapping = fyne.TextWrapWord
	t.history = widget.NewList(
		func() int { return len(t.lines) },
		func() fyne.CanvasObject {
			when := widget.NewLabel("")
			when.TextStyle.Monospace = true
			what := widget.NewLabel("")
			what.Wrapping = fyne.TextWrapWord
			return container.NewBorder(nil, nil, when, nil, what)
		},
		func(i widget.ListItemID, item fyne.CanvasObject) {
			row := item.(*fyne.Container)
			row.Objects[1].(*widget.Label).SetText(t.clock(t.lines[i].at))
			row.Objects[0].(*widget.Label).SetText(t.lines[i].text)
			t.history.SetItemHeight(i, row.MinSize().Height)
		},
	)
	return container.NewStack(t.history, container.NewVBox(t.empty))
}

// clock says when something happened: the time today, the day before that.
func (t *App) clock(at time.Time) string {
	at = at.Local()
	if y, m, d := t.now().Local().Date(); at.Year() == y && at.Month() == m && at.Day() == d {
		return at.Format("15:04")
	}
	return at.Format("02.01. 15:04")
}

func (t *App) showHistory(h api.History, err error) {
	if err != nil {
		// An older agent has no history: then there is nothing to show.
		h = api.History{}
	}
	lines := make([]historyLine, 0, len(h.Requests)+len(h.Events))
	for _, r := range h.Requests {
		lines = append(lines, historyLine{time.Unix(r.CreatedAt, 0), requestLine(r)})
	}
	for _, e := range h.Events {
		lines = append(lines, historyLine{e.At, eventLine(e)})
	}
	slices.SortStableFunc(lines, func(a, b historyLine) int { return b.at.Compare(a.at) })
	t.lines = lines
	if len(lines) == 0 {
		t.empty.Show()
	} else {
		t.empty.Hide()
	}
	t.history.Refresh()
}

// requestLine says what a request was for and how far it got.
func requestLine(r api.RequestState) string {
	what := r.Detail
	if r.Kind == api.RequestSudo || r.Kind == api.RequestScreen {
		what = lang.L("history.what."+r.Kind, map[string]any{"Minutes": r.Detail})
	}
	state := lang.L("history.state." + r.State)
	if state == "history.state."+r.State {
		state = r.State
	}
	return what + ": " + state
}

// eventLine says what changed. A change the app does not know yet shows as its
// name rather than not at all.
func eventLine(e api.DeviceEvent) string {
	key := "history.event." + e.Kind
	until := ""
	if !e.Until.IsZero() {
		until = e.Until.Local().Format("15:04")
	}
	text := lang.L(key, map[string]any{"Detail": e.Detail, "Until": until})
	if text == key {
		return e.Kind
	}
	return text
}
