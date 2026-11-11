package store

import (
	"testing"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

// A waiting task lapses by its kind: a block after hours, a package after a week.
func TestWaitingTasksLapseByKind(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	block, err := s.CreateSigningTask(ctx, "a", api.TaskAccessLock, []byte(`{}`), "admin")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := s.CreateSigningTask(ctx, "a", api.TaskPkgInstall, []byte(`{}`), "admin")
	if err != nil {
		t.Fatal(err)
	}
	queue, err := s.SigningQueue(ctx)
	if err != nil || len(queue) != 2 || queue[0].ExpiresAt == 0 {
		t.Fatalf("%+v, %v", queue, err)
	}
	if got := queue[0].ExpiresAt - queue[0].CreatedAt; got != int64((2 * time.Hour).Seconds()) {
		t.Fatalf("block waits %ds", got)
	}

	lapsed, err := s.LapseWaiting(ctx, time.Now().Add(3*time.Hour))
	if err != nil || len(lapsed) != 1 || lapsed[0].ID != block {
		t.Fatalf("%+v, %v", lapsed, err)
	}
	if again, _ := s.LapseWaiting(ctx, time.Now().Add(3*time.Hour)); len(again) != 0 {
		t.Fatal("lapsed twice")
	}
	task, err := s.GetTask(ctx, block)
	if err != nil || task.Status != "failed" || task.Output != api.TaskLapsed || task.ExpiresAt != 0 {
		t.Fatalf("%+v, %v", task, err)
	}
	if n, _ := s.FailedTasksSince(ctx, time.Now().Add(-time.Hour)); n != 0 {
		t.Fatalf("a lapsed task counts as failed: %d", n)
	}

	lapsed, _ = s.LapseWaiting(ctx, time.Now().Add(8*24*time.Hour))
	if len(lapsed) != 1 || lapsed[0].ID != pkg {
		t.Fatalf("%+v", lapsed)
	}
}

// A choice saved before the split reads as all four access types.
func TestLegacyPasskeyChoiceExpands(t *testing.T) {
	s := open(t)
	if err := s.SetPasskeyTypes(ctx, []string{api.TaskPkgInstall, api.LegacyAccessSet}, "admin"); err != nil {
		t.Fatal(err)
	}
	types, chosen, err := s.ChosenPasskeyTypes(ctx)
	if err != nil || !chosen || len(types) != 5 {
		t.Fatalf("%v %v %v", types, chosen, err)
	}
}
