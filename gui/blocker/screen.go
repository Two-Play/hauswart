package blocker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image/color"
	"net"
	"net/http"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/Two-Play/hauswart/internal/api"
)

// ControlSocket is where the agent answers the block.
const ControlSocket = "/run/hauswart/block/control.sock"

// Agent is what the block asks the agent: what to show, and the two things
// the person in front of it may do.
type Agent interface {
	State() (api.BlockState, error)
	Request(minutes int) error
	Logout() error
}

// Control talks to the agent over its socket.
type Control struct{ client *http.Client }

// NewControl reaches the agent at the socket.
func NewControl(path string) *Control {
	return &Control{client: &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}},
	}}
}

func (c *Control) State() (api.BlockState, error) {
	var state api.BlockState
	resp, err := c.client.Get("http://agent/state")
	if err != nil {
		return state, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return state, fmt.Errorf("status %d", resp.StatusCode)
	}
	return state, json.NewDecoder(resp.Body).Decode(&state)
}

func (c *Control) post(path string, body any) error {
	raw, _ := json.Marshal(body)
	resp, err := c.client.Post("http://agent"+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return errTooSoon
	}
	if resp.StatusCode == http.StatusUnprocessableEntity {
		return errRefused
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

var (
	errTooSoon = fmt.Errorf("too soon")
	// errRefused is a request the server turned away, such as from someone
	// without a Hauswart account.
	errRefused = fmt.Errorf("refused")
)

func (c *Control) Request(minutes int) error {
	return c.post("/request", map[string]int{"minutes": minutes})
}
func (c *Control) Logout() error { return c.post("/logout", struct{}{}) }

// texts are the words of the screen time block, in the language of the
// device's policy: the block runs as a service, without a desktop's language.
var screenTexts = map[string]map[string]string{
	"en": {
		"quota":          "Screen time for today is used up",
		"window":         "This is not screen time right now",
		"next":           "You can use the device again from %s.",
		"nextNever":      "No screen time is planned for the next days.",
		"logoutIn":       "You will be logged out automatically in %s. Your programs keep running until then.",
		"request":        "Ask for more time",
		"requested":      "Asked at %s, waiting for an answer.",
		"approved":       "More time was granted, one moment.",
		"denied":         "The request was denied.",
		"tooSoon":        "You asked a moment ago. Please wait a few minutes.",
		"failed":         "The request did not get through. Try again later.",
		"refused":        "Requests are not possible for this account. Ask an adult or an admin directly.",
		"logout":         "Log out now",
		"logoutConfirm":  "Log out now? Anything not saved is lost.",
		"logoutTitle":    "Log out",
		"minutes":        "%d minutes",
		"day":            "Monday,Tuesday,Wednesday,Thursday,Friday,Saturday,Sunday",
		"today":          "today",
		"tomorrow":       "tomorrow",
		"dateFormat":     "%s, %s",
		"clock":          "15:04",
		"blockedAccount": "Blocked for %s",
	},
	"de": {
		"quota":          "Die Bildschirmzeit für heute ist aufgebraucht",
		"window":         "Gerade ist keine Bildschirmzeit",
		"next":           "Du kannst das Gerät wieder ab %s benutzen.",
		"nextNever":      "Für die nächsten Tage ist keine Bildschirmzeit geplant.",
		"logoutIn":       "Du wirst in %s automatisch abgemeldet. Deine Programme laufen bis dahin weiter.",
		"request":        "Mehr Zeit anfragen",
		"requested":      "Angefragt um %s, warte auf Antwort.",
		"approved":       "Mehr Zeit ist genehmigt, einen Moment.",
		"denied":         "Die Anfrage wurde abgelehnt.",
		"tooSoon":        "Du hast eben schon gefragt. Bitte warte ein paar Minuten.",
		"failed":         "Die Anfrage kam nicht durch. Versuch es später noch einmal.",
		"refused":        "Für dieses Konto sind keine Anfragen möglich. Frag direkt eine erwachsene Person oder einen Admin.",
		"logout":         "Jetzt abmelden",
		"logoutConfirm":  "Jetzt abmelden? Was nicht gespeichert ist, geht verloren.",
		"logoutTitle":    "Abmelden",
		"minutes":        "%d Minuten",
		"day":            "Montag,Dienstag,Mittwoch,Donnerstag,Freitag,Samstag,Sonntag",
		"today":          "heute",
		"tomorrow":       "morgen",
		"dateFormat":     "%s, %s",
		"clock":          "15:04",
		"blockedAccount": "Gesperrt für %s",
	},
}

func text(language, key string) string {
	if t, ok := screenTexts[language][key]; ok {
		return t
	}
	return screenTexts["en"][key]
}

// when says a moment the way people say it: today, tomorrow or a weekday.
func when(language string, t, now time.Time) string {
	clock := t.Local().Format(text(language, "clock"))
	t, now = t.Local(), now.Local()
	day := strings.Split(text(language, "day"), ",")[(int(t.Weekday())+6)%7]
	switch {
	case t.YearDay() == now.YearDay() && t.Year() == now.Year():
		day = text(language, "today")
	case t.YearDay() == now.AddDate(0, 0, 1).YearDay() && t.Year() == now.AddDate(0, 0, 1).Year():
		day = text(language, "tomorrow")
	}
	return fmt.Sprintf(text(language, "dateFormat"), day, clock)
}

// countdown is a duration as minutes and seconds.
func countdown(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	return fmt.Sprintf("%d:%02d", int(d/time.Minute), int(d%time.Minute/time.Second))
}

// ScreenView is the block for someone whose screen time ended.
type ScreenView struct {
	agent  Agent
	window fyne.Window
	now    func() time.Time

	title, subtitle, next, logoutIn, status *canvas.Text
	minutes                                 *widget.Select
	request, logout                         *widget.Button
	state                                   api.BlockState
	// message is the outcome of the last click, until the state says more.
	message string
	choices map[string]int
}

func whiteText(size float32) *canvas.Text {
	t := canvas.NewText("", color.White)
	t.TextSize = size
	t.Alignment = fyne.TextAlignCenter
	return t
}

// NewScreenView builds the view; Update fills it.
func NewScreenView(agent Agent, window fyne.Window) *ScreenView {
	v := &ScreenView{agent: agent, window: window, now: time.Now, choices: map[string]int{}}
	v.title = whiteText(40)
	v.title.TextStyle.Bold = true
	v.subtitle = whiteText(20)
	v.next = whiteText(24)
	v.logoutIn = whiteText(18)
	v.status = whiteText(18)
	v.minutes = widget.NewSelect(nil, nil)
	v.request = widget.NewButton("", v.ask)
	v.request.Importance = widget.HighImportance
	v.logout = widget.NewButton("", v.confirmLogout)
	return v
}

// Content is the layout of the view.
func (v *ScreenView) Content() fyne.CanvasObject {
	buttons := container.NewHBox(layout.NewSpacer(), v.minutes, v.request, v.logout, layout.NewSpacer())
	footer := canvas.NewText("Hauswart", color.Gray{Y: 0x90})
	footer.TextSize = 14
	footer.Alignment = fyne.TextAlignCenter
	return container.NewStack(canvas.NewRectangle(color.Black), container.NewVBox(
		layout.NewSpacer(), v.title, v.subtitle, v.next, layout.NewSpacer(),
		buttons, v.status, v.logoutIn, layout.NewSpacer(), footer))
}

// Update shows a new state.
func (v *ScreenView) Update(state api.BlockState) {
	v.state = state
	language, now := state.Language, v.now()
	v.title.Text = text(language, state.Reason)
	v.subtitle.Text = fmt.Sprintf(text(language, "blockedAccount"), state.User)
	if state.Next.IsZero() {
		v.next.Text = text(language, "nextNever")
	} else {
		v.next.Text = fmt.Sprintf(text(language, "next"), when(language, state.Next, now))
	}
	v.logoutIn.Text = fmt.Sprintf(text(language, "logoutIn"), countdown(state.LogoutAt.Sub(now)))
	options := []string{}
	for _, m := range []int{15, 30, 60} {
		label := fmt.Sprintf(text(language, "minutes"), m)
		v.choices[label] = m
		options = append(options, label)
	}
	v.minutes.Options = options
	if v.minutes.Selected == "" {
		v.minutes.SetSelected(options[0])
	}
	v.request.SetText(text(language, "request"))
	v.logout.SetText(text(language, "logout"))
	switch {
	case state.RequestState == api.RequestDenied:
		v.status.Text = text(language, "denied")
	case state.RequestState == api.RequestApproved || state.RequestState == api.RequestDone:
		v.status.Text = text(language, "approved")
	case !state.RequestedAt.IsZero():
		v.status.Text = fmt.Sprintf(text(language, "requested"), state.RequestedAt.Local().Format(text(language, "clock")))
	default:
		v.status.Text = v.message
	}
	if !state.RequestedAt.IsZero() && state.RequestState != api.RequestDenied {
		v.request.Disable()
	} else {
		v.request.Enable()
	}
	for _, t := range []*canvas.Text{v.title, v.subtitle, v.next, v.logoutIn, v.status} {
		t.Refresh()
	}
}

func (v *ScreenView) ask() {
	minutes := v.choices[v.minutes.Selected]
	if minutes == 0 {
		return
	}
	v.request.Disable()
	go func() {
		err := v.agent.Request(minutes)
		fyne.Do(func() {
			switch {
			case err == errTooSoon:
				v.message = text(v.state.Language, "tooSoon")
			case err == errRefused:
				v.message = text(v.state.Language, "refused")
			case err != nil:
				v.message = text(v.state.Language, "failed")
				v.request.Enable()
			default:
				v.message = ""
			}
			v.status.Text = v.message
			v.status.Refresh()
		})
	}()
}

func (v *ScreenView) confirmLogout() {
	language := v.state.Language
	dialog.ShowConfirm(text(language, "logoutTitle"), text(language, "logoutConfirm"), func(yes bool) {
		if yes {
			go v.agent.Logout()
		}
	}, v.window)
}
