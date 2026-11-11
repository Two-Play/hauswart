package server

import (
	"bytes"
	"fmt"
	"net/http"
	"slices"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/sign"
	"github.com/Two-Play/hauswart/internal/store"
)

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.Handle("POST /api/passkey-batch/challenge", s.approver(s.handleBatchChallenge))
		mux.Handle("POST /api/passkey-batch/approval", s.approver(s.handleBatchApproval))
	})
}

// batchItem is one task of a batch, as the approver confirms it.
type batchItem struct {
	Task     string `json:"task"`
	Envelope []byte `json:"envelope"`
	Hostname string `json:"hostname"`
}

// batchTasks reads the tasks of a batch: 2 to sign.MaxPasskeyBatch, each once.
// A live terminal stays single, since it belongs to whoever opened it.
func batchTasks(w http.ResponseWriter, ids []string) bool {
	if len(ids) < 2 || len(ids) > sign.MaxPasskeyBatch {
		fail(w, http.StatusBadRequest, api.ErrBatchSize, fmt.Sprint(sign.MaxPasskeyBatch))
		return false
	}
	for i, id := range ids {
		if slices.Contains(ids[:i], id) {
			fail(w, http.StatusBadRequest, api.ErrBatchSize, fmt.Sprint(sign.MaxPasskeyBatch))
			return false
		}
	}
	return true
}

// handleBatchChallenge prepares several tasks for one touch. Each goes through
// the checks of a single approval. The passkeys offered are those pinned on
// every device in the batch, so one touch can approve all of it.
func (s *Server) handleBatchChallenge(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		Tasks []string `json:"tasks"`
	}
	if !readJSON(w, r, &in) || !batchTasks(w, in.Tasks) {
		return
	}
	rpID, _, ok := s.relyingParty()
	if !ok {
		fail(w, http.StatusConflict, api.ErrNoPasskeyHost)
		return
	}
	items := make([]batchItem, 0, len(in.Tasks))
	var credentials [][]byte
	for i, id := range in.Tasks {
		p, refused := s.preparePasskey(r.Context(), u, id)
		if refused != nil {
			s.refuse(w, refused)
			return
		}
		if p.task.Type == api.TaskTerminalOpen {
			fail(w, http.StatusConflict, api.ErrBatchTerminal)
			return
		}
		if i == 0 {
			credentials = p.credentials
		} else {
			credentials = slices.DeleteFunc(credentials, func(c []byte) bool {
				return !slices.ContainsFunc(p.credentials, func(o []byte) bool { return bytes.Equal(o, c) })
			})
		}
		items = append(items, batchItem{Task: id, Envelope: p.envelope, Hostname: p.task.Hostname})
	}
	if len(credentials) == 0 {
		fail(w, http.StatusConflict, api.ErrPasskeyNotPinned)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "credentials": credentials, "rp_id": rpID})
}

// batchResult says what became of each task.
type batchResult struct {
	Task string `json:"task"`
	OK   bool   `json:"ok"`
	Code string `json:"code,omitempty"`
}

// handleBatchApproval takes one assertion over the hashes of all envelopes, in
// the order they were shown, and passes each task on with the whole list. Each
// device checks that its envelope is in the list and the assertion covers it.
// A task that fails here does not hold up the others.
func (s *Server) handleBatchApproval(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		Tasks     []string       `json:"tasks"`
		Assertion sign.Assertion `json:"assertion"`
	}
	if !readJSON(w, r, &in) || !batchTasks(w, in.Tasks) {
		return
	}
	tasks := make([]store.WaitingRow, 0, len(in.Tasks))
	hashes := make([][]byte, 0, len(in.Tasks))
	for _, id := range in.Tasks {
		task, err := s.store.WaitingTask(r.Context(), id)
		if err != nil || len(task.Envelope()) == 0 {
			fail(w, http.StatusConflict, api.ErrNotWaiting)
			return
		}
		tasks = append(tasks, task)
		hashes = append(hashes, sign.EnvelopeHash(task.Envelope()))
	}
	pins, err := s.approverPins(r.Context(), u)
	if err != nil {
		s.internal(w, err)
		return
	}
	results := make([]batchResult, 0, len(tasks))
	woken := map[string]bool{}
	for _, task := range tasks {
		signed := sign.Signed{Envelope: task.Envelope(), Passkey: &in.Assertion, Batch: hashes}
		used, refused := s.releasePasskey(r.Context(), u, task, signed, pins)
		if refused != nil {
			if refused.status == http.StatusInternalServerError {
				s.internal(w, refused.err)
				return
			}
			code := api.ErrPasskeyRefused
			if e, ok := refused.err.(*api.Error); ok {
				code = e.Code
			}
			results = append(results, batchResult{Task: task.ID, Code: code})
			continue
		}
		s.audit(r, u.Username, "task.passkey_approved", fmt.Sprintf("%s %s, one of %d", task.ID, used.Name, len(tasks)))
		results = append(results, batchResult{Task: task.ID, OK: true})
		woken[task.DeviceID] = true
	}
	for device := range woken {
		s.wake(device)
	}
	writeJSON(w, http.StatusOK, results)
}
