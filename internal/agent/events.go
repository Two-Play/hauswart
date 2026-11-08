package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

const (
	eventsFile = "events.json"
	// keptEvents is how many changes the device remembers, for all people together.
	keptEvents = 200
	// sudoWarning is how long before its end a sudo grant earns a warning.
	sudoWarning = 5 * time.Minute
	// requestInterval is how often the agent asks how requests stand, while
	// someone is at the desktop to be told.
	requestInterval = time.Minute
	// popupDetail keeps a list of packages in a popup short.
	popupDetail = 120
)

// eventTexts are the popups, in the language of the policy like screen time.
// The desktop app has its own texts for its history, in the desktop's language.
var eventTexts = map[string]map[string]string{
	"en": {
		api.EventSudoGranted:       "You have admin rights until {time}.",
		api.EventSudoRevoked:       "Your admin rights were taken back.",
		api.EventSudoExpiring:      "Your admin rights end at {time}.",
		api.EventSudoExpired:       "Your admin rights have ended.",
		api.EventSoftwareInstalled: "Installed: {detail}",
		api.EventSoftwareRemoved:   "Removed: {detail}",
		api.EventSoftwareUpgraded:  "The software on this device was updated.",
		api.EventSoftwareFailed:    "A software change did not work: {detail}",
		api.EventUpdateFailed:      "The update of this device did not work.",
		api.EventAccountLocked:     "Your account was locked.",
		api.EventAccountUnlocked:   "Your account was unlocked.",
		api.EventAccountPassword:   "Your password was changed.",
		api.EventGroupAdded:        "You are now in the group {detail}.",
		api.EventGroupRemoved:      "You are no longer in the group {detail}.",
		api.EventPolicyChanged:     "This device has new rules.",
		api.EventPolicyCleared:     "The rules of this device were removed.",
		api.RequestSigning:         "Your request for {detail} was approved and waits for a signature.",
		api.RequestDenied:          "Your request for {detail} was denied.",
		api.RequestFailed:          "Your request for {detail} was approved, but did not work.",
		api.RequestDone:            "Your request for {detail} is done.",
	},
	"de": {
		api.EventSudoGranted:       "Du hast Admin-Rechte bis {time}.",
		api.EventSudoRevoked:       "Deine Admin-Rechte wurden zurückgenommen.",
		api.EventSudoExpiring:      "Deine Admin-Rechte enden um {time}.",
		api.EventSudoExpired:       "Deine Admin-Rechte sind abgelaufen.",
		api.EventSoftwareInstalled: "Installiert: {detail}",
		api.EventSoftwareRemoved:   "Entfernt: {detail}",
		api.EventSoftwareUpgraded:  "Die Software auf diesem Gerät wurde aktualisiert.",
		api.EventSoftwareFailed:    "Eine Änderung an der Software hat nicht geklappt: {detail}",
		api.EventUpdateFailed:      "Das Update dieses Geräts hat nicht geklappt.",
		api.EventAccountLocked:     "Dein Konto wurde gesperrt.",
		api.EventAccountUnlocked:   "Dein Konto wurde entsperrt.",
		api.EventAccountPassword:   "Dein Passwort wurde geändert.",
		api.EventGroupAdded:        "Du bist jetzt in der Gruppe {detail}.",
		api.EventGroupRemoved:      "Du bist nicht mehr in der Gruppe {detail}.",
		api.EventPolicyChanged:     "Für dieses Gerät gelten neue Regeln.",
		api.EventPolicyCleared:     "Die Regeln für dieses Gerät wurden entfernt.",
		api.RequestSigning:         "Deine Anfrage für {detail} wurde genehmigt und wartet auf eine Signatur.",
		api.RequestDenied:          "Deine Anfrage für {detail} wurde abgelehnt.",
		api.RequestFailed:          "Deine Anfrage für {detail} wurde genehmigt, hat aber nicht geklappt.",
		api.RequestDone:            "Deine Anfrage für {detail} ist erledigt.",
	},
}

// requestNames say what a request was for in a popup, when its detail alone
// would not, such as the minutes of a sudo request.
var requestNames = map[string]map[string]string{
	"en": {api.RequestSudo: "admin rights", api.RequestScreen: "more screen time"},
	"de": {api.RequestSudo: "Admin-Rechte", api.RequestScreen: "mehr Bildschirmzeit"},
}

func eventText(language, kind, detail string, until time.Time) string {
	texts, ok := eventTexts[language]
	if !ok {
		texts = eventTexts["en"]
	}
	clock := ""
	if !until.IsZero() {
		clock = until.Local().Format("15:04")
	}
	// A replacer and not Sprintf, because most texts use neither.
	return strings.NewReplacer("{detail}", clip(detail, popupDetail), "{time}", clock).Replace(texts[kind])
}

func requestName(language string, r api.RequestState) string {
	names, ok := requestNames[language]
	if !ok {
		names = requestNames["en"]
	}
	if name, ok := names[r.Kind]; ok {
		return name
	}
	return r.Detail
}

// Notices tells people at the device what Hauswart changed for them, in a popup
// and in the history of the desktop app. It forgets nothing that matters: a
// lost popup costs a moment of surprise, never a right.
type Notices struct {
	exec     *Executor
	log      *slog.Logger
	path     string
	language func() string
	now      func() time.Time

	mu       sync.Mutex
	state    noticeState
	requests []api.RequestState
	// asked is when the server last said how the requests stand.
	asked time.Time
	// warned is the end of the grant each person was warned about.
	warned map[string]time.Time
	// told are the requests whose task already showed a popup of its own.
	told map[string]bool
	// popups counts the popups on their way, for tests.
	popups sync.WaitGroup
}

// noticeState is what survives a restart.
type noticeState struct {
	Events []api.DeviceEvent `json:"events"`
	// Seen is the last state of each request, so a restart tells nothing twice.
	// Nil means the device never asked, and then the first answer tells nothing.
	Seen map[string]string `json:"seen"`
}

func OpenNotices(dir string, exec *Executor, language func() string, log *slog.Logger) *Notices {
	n := &Notices{
		exec: exec, log: log, path: dir + "/" + eventsFile, language: language, now: time.Now,
		warned: map[string]time.Time{}, told: map[string]bool{},
	}
	raw, err := os.ReadFile(n.path)
	if err == nil {
		err = json.Unmarshal(raw, &n.state)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		// A broken file costs the history, nothing else.
		log.Warn("starting with an empty history", "err", err)
		n.state = noticeState{}
	}
	return n
}

// record keeps an event and shows it. Device-wide events go to everyone at a
// desktop.
func (n *Notices) record(ctx context.Context, e api.DeviceEvent, urgency string) {
	e.At = n.now()
	n.mu.Lock()
	n.state.Events = append(n.state.Events, e)
	if len(n.state.Events) > keptEvents {
		n.state.Events = slices.Clone(n.state.Events[len(n.state.Events)-keptEvents:])
	}
	n.saveLocked()
	n.mu.Unlock()
	n.show(ctx, e.User, eventText(n.language(), e.Kind, e.Detail, e.Until), urgency)
}

// show runs apart from the caller: a person's session bus is theirs to slow down.
func (n *Notices) show(ctx context.Context, user, message, urgency string) {
	n.popups.Go(func() { n.exec.popup(context.WithoutCancel(ctx), user, message, urgency) })
}

func (n *Notices) saveLocked() {
	raw, err := json.Marshal(n.state)
	if err == nil {
		err = writeAtomic(n.path, raw, 0o600)
	}
	if err != nil {
		n.log.Warn("saving the history failed", "err", err)
	}
}

// AfterTask tells people what a finished task changed. Only what the task
// really did counts, so a refused task tells nothing.
func (n *Notices) AfterTask(ctx context.Context, task api.Task, result api.TaskResult) {
	event, ok := taskEvent(task, result)
	if !ok {
		return
	}
	if task.Request != "" {
		n.mu.Lock()
		n.told[task.Request] = true
		n.mu.Unlock()
	}
	if event.Kind == "" {
		return
	}
	if event.Kind == api.EventSudoGranted {
		n.mu.Lock()
		delete(n.warned, event.User)
		n.mu.Unlock()
	}
	urgency := urgencyNormal
	if event.Kind == api.EventSoftwareFailed || event.Kind == api.EventUpdateFailed || event.Kind == api.EventAccountLocked {
		urgency = urgencyCritical
	}
	n.record(ctx, event, urgency)
}

// taskEvent says what a task means to the people at the device. The second
// result is false for tasks nobody hears about. An event without a kind is a
// task that tells people on its own, such as more screen time.
func taskEvent(task api.Task, result api.TaskResult) (api.DeviceEvent, bool) {
	var packages api.PackagesPayload
	var person api.UserPayload
	var group api.GroupPayload
	var sudo api.SudoGrantPayload
	switch task.Type {
	case api.TaskPkgInstall, api.TaskPkgRemove, api.TaskFlatpakInstall:
		if json.Unmarshal(task.Payload, &packages) != nil {
			return api.DeviceEvent{}, false
		}
		detail := strings.Join(packages.Packages, ", ")
		switch {
		case !result.OK:
			return api.DeviceEvent{Kind: api.EventSoftwareFailed, Detail: detail}, true
		case task.Type == api.TaskPkgRemove:
			return api.DeviceEvent{Kind: api.EventSoftwareRemoved, Detail: detail}, true
		}
		return api.DeviceEvent{Kind: api.EventSoftwareInstalled, Detail: detail}, true
	case api.TaskPkgUpgrade:
		if !result.OK {
			return api.DeviceEvent{Kind: api.EventUpdateFailed}, true
		}
		return api.DeviceEvent{Kind: api.EventSoftwareUpgraded}, true
	case api.TaskScreenExtend:
		return api.DeviceEvent{}, result.OK
	}
	if !result.OK {
		return api.DeviceEvent{}, false
	}
	switch task.Type {
	case api.TaskSudoGrant:
		if json.Unmarshal(task.Payload, &sudo) != nil {
			return api.DeviceEvent{}, false
		}
		return api.DeviceEvent{Kind: api.EventSudoGranted, User: sudo.User, Until: sudo.ExpiresAt}, true
	case api.TaskSudoRevoke, api.TaskUserLock, api.TaskUserUnlock, api.TaskUserPassword:
		if json.Unmarshal(task.Payload, &person) != nil || person.User == "" {
			return api.DeviceEvent{}, false
		}
		kind := map[string]string{
			api.TaskSudoRevoke:   api.EventSudoRevoked,
			api.TaskUserLock:     api.EventAccountLocked,
			api.TaskUserUnlock:   api.EventAccountUnlocked,
			api.TaskUserPassword: api.EventAccountPassword,
		}[task.Type]
		return api.DeviceEvent{Kind: kind, User: person.User}, true
	case api.TaskGroupAdd, api.TaskGroupRemove:
		if json.Unmarshal(task.Payload, &group) != nil || group.User == "" {
			return api.DeviceEvent{}, false
		}
		kind := api.EventGroupAdded
		if task.Type == api.TaskGroupRemove {
			kind = api.EventGroupRemoved
		}
		return api.DeviceEvent{Kind: kind, User: group.User, Detail: group.Group}, true
	case api.TaskPolicySet:
		return api.DeviceEvent{Kind: api.EventPolicyChanged}, true
	case api.TaskPolicyClear:
		return api.DeviceEvent{Kind: api.EventPolicyCleared}, true
	}
	return api.DeviceEvent{}, false
}

// CheckGrants warns before a sudo grant ends, once per grant, and tells who
// lost one. The grant loop calls it after revoking.
func (n *Notices) CheckGrants(ctx context.Context, grants map[string]time.Time, revoked []string) {
	for _, user := range revoked {
		n.mu.Lock()
		delete(n.warned, user)
		n.mu.Unlock()
		n.record(ctx, api.DeviceEvent{Kind: api.EventSudoExpired, User: user}, urgencyNormal)
	}
	now := n.now()
	for user, end := range grants {
		if !now.Before(end) || end.Sub(now) > sudoWarning {
			continue
		}
		n.mu.Lock()
		due := !n.warned[user].Equal(end)
		n.warned[user] = end
		n.mu.Unlock()
		if due {
			n.record(ctx, api.DeviceEvent{Kind: api.EventSudoExpiring, User: user, Until: end}, urgencyCritical)
		}
	}
}

// requestPopup says whether a request in this state earns a popup. Approved
// requests tell through their task, so only what no task shows is left.
func requestPopup(state string, told bool) bool {
	switch state {
	case api.RequestSigning, api.RequestDenied:
		return true
	case api.RequestFailed, api.RequestDone:
		return !told
	}
	return false
}

// SetRequests takes what the server says about the requests of this device and
// tells each person what changed about theirs.
func (n *Notices) SetRequests(ctx context.Context, requests []api.RequestState) {
	n.mu.Lock()
	first := n.state.Seen == nil
	seen := make(map[string]string, len(requests))
	var popups []api.RequestState
	for _, r := range requests {
		seen[r.ID] = r.State
		if before, known := n.state.Seen[r.ID]; first || (known && before == r.State) {
			continue
		}
		if requestPopup(r.State, n.told[r.ID]) {
			popups = append(popups, r)
		}
	}
	for id := range n.told {
		if _, ok := seen[id]; !ok {
			delete(n.told, id)
		}
	}
	n.requests = requests
	n.asked = n.now()
	n.state.Seen = seen
	n.saveLocked()
	n.mu.Unlock()
	language := n.language()
	for _, r := range popups {
		urgency := urgencyNormal
		if r.State == api.RequestDenied || r.State == api.RequestFailed {
			urgency = urgencyCritical
		}
		n.show(ctx, r.User, eventText(language, r.State, requestName(language, r), time.Time{}), urgency)
	}
}

// Stale says that the requests are older than the loop would let them get.
func (n *Notices) Stale() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.now().Sub(n.asked) >= requestInterval
}

// History is what one person may see: their requests, their events and those
// of the whole device.
func (n *Notices) History(user string) api.History {
	n.mu.Lock()
	defer n.mu.Unlock()
	h := api.History{Requests: []api.RequestState{}, Events: []api.DeviceEvent{}}
	for _, r := range n.requests {
		if r.User == user {
			h.Requests = append(h.Requests, r)
		}
	}
	for i := len(n.state.Events) - 1; i >= 0; i-- {
		if e := n.state.Events[i]; e.User == "" || e.User == user {
			h.Events = append(h.Events, e)
		}
	}
	return h
}
