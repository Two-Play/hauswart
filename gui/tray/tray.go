// Package tray is the desktop app of a member: how much screen time is
// left, what is connected, and a way to ask for something.
package tray

import (
	_ "embed"
	"errors"
	"fmt"
	"net/url"
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
)

// Agent is what the app needs from the agent on this device.
type Agent interface {
	Status() (api.UserStatus, error)
	Request(api.UserRequest) (string, error)
}

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

	status api.UserStatus

	screen   *widget.Label
	shares   *widget.Label
	notice   *widget.Label
	tabs     *container.AppTabs
	request  *container.TabItem
	cloud    *container.TabItem
	kind     *widget.Select
	detail   *widget.Entry
	reason   *widget.Entry
	result   *widget.Label
	cloudURL *widget.Label
	cloudTip *widget.Label
	password *widget.Entry
	saveKey  *widget.Button
	saved    *widget.Label
	menuTime *fyne.MenuItem
	menu     *fyne.Menu
}

// New builds the app. Refresh fills it.
func New(a fyne.App, agent Agent, keyring Keyring) *App {
	t := &App{app: a, agent: agent, keyring: keyring, now: time.Now, background: func(f func()) { go f() }}
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
	t.reason = widget.NewEntry()
	t.result = widget.NewLabel("")
	t.result.Wrapping = fyne.TextWrapWord
	t.kind = widget.NewSelect(labels, func(string) { t.showDetailHint() })
	t.kind.SetSelectedIndex(0)
	form := widget.NewForm(
		widget.NewFormItem(lang.L("request.kind"), t.kind),
		widget.NewFormItem("", t.detail),
		widget.NewFormItem(lang.L("request.reason"), t.reason),
	)
	return container.NewVBox(form, widget.NewButton(lang.L("request.send"), t.send), t.result)
}

func (t *App) selectedKind() string {
	if i := t.kind.SelectedIndex(); i >= 0 {
		return kinds[i]
	}
	return kinds[0]
}

func timed(kind string) bool { return kind == "sudo" || kind == api.RequestScreen }

func (t *App) showDetailHint() {
	if t.detail == nil {
		return
	}
	if timed(t.selectedKind()) {
		t.detail.SetPlaceHolder(lang.L("request.detail.minutes"))
	} else {
		t.detail.SetPlaceHolder(lang.L("request.detail.packages"))
	}
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
	t.password.SetPlaceHolder(lang.L("nextcloud.password"))
	t.saveKey = widget.NewButton(lang.L("nextcloud.save"), t.saveNextcloud)
	t.saved = widget.NewLabel("")
	t.saved.Wrapping = fyne.TextWrapWord
	return container.NewVBox(t.cloudURL, t.cloudTip, t.password, t.saveKey, t.saved)
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

	t.shares.SetText(lang.L("shares.none"))
	if len(status.Shares) > 0 {
		t.shares.SetText(strings.Join(status.Shares, "\n"))
	}
	t.notice.SetText("")
	if status.PolicyIssues {
		t.notice.SetText(lang.L("policy.issues"))
	}
	t.showCloud(status.Nextcloud)
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
