package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

// blockFixture is the control service with anna behind the block.
func blockFixture(t *testing.T) (*blockControlService, *[]api.DeviceRequest, *fakeRunner) {
	t.Helper()
	pe, _ := newEngine(t)
	now := monday(20, 0)
	pe.block("1001", "anna", api.ScreenReasonWindow, monday(15, 0).AddDate(0, 0, 1), now)
	e, runner := newExecutor(t)
	access := &Access{exec: e, log: quiet(), now: func() time.Time { return now }, screen: pe, blockedFor: "anna"}
	var sent []api.DeviceRequest
	service := &blockControlService{access: access, policy: pe, exec: e, blockUID: 990, now: func() time.Time { return now },
		send: func(_ context.Context, r api.DeviceRequest) (string, error) {
			sent = append(sent, r)
			return api.RequestOpen, nil
		},
		history: func(string) api.History { return api.History{} },
	}
	return service, &sent, runner
}

func callBlock(t *testing.T, s *blockControlService, uid uint32, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), peerKey{}, uid))
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, req)
	return w
}

func TestBlockControlIsForTheBlockAlone(t *testing.T) {
	s, _, _ := blockFixture(t)
	if w := callBlock(t, s, 1001, "GET", "/state", ""); w.Code != http.StatusForbidden {
		t.Fatalf("the blocked person reached the block's socket: %d", w.Code)
	}
	w := callBlock(t, s, 990, "GET", "/state", "")
	var state api.BlockState
	json.Unmarshal(w.Body.Bytes(), &state)
	if w.Code != http.StatusOK || state.Kind != api.BlockScreen || state.User != "anna" || state.Reason != api.ScreenReasonWindow ||
		!state.LogoutAt.Equal(monday(20, 10)) || state.Next.IsZero() {
		t.Fatalf("state %d %s", w.Code, w.Body)
	}
}

func TestBlockAsksForTimeAsTheBlockedPerson(t *testing.T) {
	s, sent, _ := blockFixture(t)
	if w := callBlock(t, s, 990, "POST", "/request", `{"minutes":45}`); w.Code != http.StatusBadRequest {
		t.Fatalf("odd minutes: %d", w.Code)
	}
	if w := callBlock(t, s, 990, "POST", "/request", `{"minutes":30}`); w.Code != http.StatusOK {
		t.Fatalf("request: %d %s", w.Code, w.Body)
	}
	if len(*sent) != 1 || (*sent)[0].User != "anna" || (*sent)[0].Kind != api.RequestScreen || (*sent)[0].Detail != "30" {
		t.Fatalf("sent %+v", *sent)
	}
	if w := callBlock(t, s, 990, "POST", "/request", `{"minutes":30}`); w.Code != http.StatusTooManyRequests {
		t.Fatalf("asked again at once: %d", w.Code)
	}
	var state api.BlockState
	json.Unmarshal(callBlock(t, s, 990, "GET", "/state", "").Body.Bytes(), &state)
	if state.RequestedAt.IsZero() || state.RequestState != api.RequestOpen {
		t.Fatalf("state %+v", state)
	}
}

func TestBlockLogsTheBlockedPersonOut(t *testing.T) {
	s, _, runner := blockFixture(t)
	if w := callBlock(t, s, 990, "POST", "/logout", ""); w.Code != http.StatusNoContent {
		t.Fatalf("logout: %d %s", w.Code, w.Body)
	}
	found := false
	for _, call := range runner.calls {
		if strings.Join(call, " ") == "loginctl terminate-user anna" {
			found = true
		}
	}
	if !found {
		t.Fatalf("calls %v", runner.calls)
	}
}
