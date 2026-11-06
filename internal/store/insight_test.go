package store

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

func TestSamplesOnePerMinute(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	at := time.Now().Truncate(time.Minute)
	for i := range 5 {
		if err := s.AddSample(ctx, "a", at.Add(time.Duration(i)*time.Second), api.Report{MemUsed: uint64(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}
	samples, err := s.History(ctx, "a", at.Add(-time.Hour), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 || samples[0].MemUsed != 1 || samples[0].Time != at.Unix() {
		t.Errorf("got %+v", samples)
	}
}

func TestHistoryAveragesPerStep(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	device(t, s, "b")
	start := time.Unix(1_800_000_000, 0).Truncate(5 * time.Minute)
	for i := range 10 {
		r := api.Report{Load1: float64(i), MemUsed: uint64(i) * 10, MemTotal: 100, DiskUsed: 50, DiskTotal: 200}
		if err := s.AddSample(ctx, "a", start.Add(time.Duration(i)*time.Minute), r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AddSample(ctx, "b", start, api.Report{MemUsed: 999}); err != nil {
		t.Fatal(err)
	}
	samples, err := s.History(ctx, "a", start.Add(time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 {
		t.Fatalf("got %+v", samples)
	}
	first, second := samples[0], samples[1]
	if first.Time != start.Unix() || first.Load1 != 2.5 || first.MemUsed != 25 || first.MemTotal != 100 {
		t.Errorf("got %+v", first)
	}
	if second.Time != start.Add(5*time.Minute).Unix() || second.Load1 != 7 || second.DiskTotal != 200 {
		t.Errorf("got %+v", second)
	}
}

func TestHugeValuesFromADeviceDoNotBreakAReport(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	if err := s.AddSample(ctx, "a", time.Now(), api.Report{MemUsed: 1 << 63}); err != nil {
		t.Error(err)
	}
}

func TestCleanupDropsOldInsight(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	now := time.Now()
	for _, age := range []time.Duration{SampleRetention + time.Hour, SampleRetention - time.Hour} {
		if err := s.AddSample(ctx, "a", now.Add(-age), api.Report{}); err != nil {
			t.Fatal(err)
		}
	}
	finish := func(taskType string, age time.Duration) string {
		id, err := s.CreateTask(ctx, "a", taskType, []byte(`{}`), "admin")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.ClaimTask(ctx, "a"); err != nil {
			t.Fatal(err)
		}
		result := api.TaskResult{OK: true, Output: "kept", Data: json.RawMessage(`{"x":1}`)}
		if err := s.FinishTask(ctx, "a", id, result); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`UPDATE tasks SET finished_at = ? WHERE id = ?`, now.Add(-age).Unix(), id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	oldLogs := finish(api.TaskLogsFetch, 2*time.Hour)
	freshLogs := finish(api.TaskLogsFetch, time.Minute)
	otherTask := finish(api.TaskPkgUpgrade, 2*time.Hour)

	if err := s.Cleanup(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	samples, err := s.History(ctx, "a", now.Add(-30*24*time.Hour), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 {
		t.Errorf("got %d samples", len(samples))
	}
	for id, wantData := range map[string]bool{oldLogs: false, freshLogs: true, otherTask: true} {
		task, err := s.GetTask(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if (task.Data != nil) != wantData || task.Output != "kept" {
			t.Errorf("%s: got %+v", task.Type, task)
		}
	}
}

func TestGetTaskUnknown(t *testing.T) {
	if _, err := open(t).GetTask(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v", err)
	}
}

func TestSamplesGoWithTheirDevice(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	if err := s.AddSample(ctx, "a", time.Now(), api.Report{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM devices WHERE id = 'a'`); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM device_samples`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d rows, %v", n, err)
	}
}
