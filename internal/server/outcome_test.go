package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Two-Play/hauswart/internal/api"
)

func TestFailedRequestSaysWhy(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	e.assign("anna", id)
	admin, anna := e.login("admin"), e.login("anna")
	_, filed := file(t, e, anna, id, "flatpak", "org.mozilla.firefox")
	if code, data := e.do(admin, "POST", "/api/requests/"+filed["id"]+"/approve", nil); code != http.StatusNoContent {
		t.Fatalf("%d %s", code, data)
	}
	outcome := func(c *http.Client) (string, string) {
		_, data := e.do(c, "GET", "/api/requests", nil)
		var list []struct {
			Outcome       string `json:"outcome"`
			OutcomeDetail string `json:"outcome_detail"`
		}
		json.Unmarshal(data, &list)
		return list[0].Outcome, list[0].OutcomeDetail
	}
	if state, _ := outcome(admin); state != api.RequestRunning {
		t.Fatalf("got %s", state)
	}
	_, data := e.do(agent, "GET", "/agent/tasks?wait=0", nil)
	var task api.Task
	json.Unmarshal(data, &task)
	e.do(agent, "POST", "/agent/tasks/"+task.ID+"/result", api.TaskResult{OK: false, Output: "flatpak is not installed"})
	if state, why := outcome(admin); state != api.RequestFailed || why != "flatpak is not installed" {
		t.Fatalf("admin sees %s %q", state, why)
	}
	if state, why := outcome(anna); state != api.RequestFailed || why != "" {
		t.Fatalf("anna sees %s %q", state, why)
	}
}
