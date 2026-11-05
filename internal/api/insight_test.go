package api

import (
	"encoding/json"
	"testing"
	"time"
)

func TestWarnings(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time {
		expires := now.Add(d)
		return &expires
	}
	day := 24 * time.Hour
	for name, c := range map[string]struct {
		report Report
		want   []Warning
	}{
		"nothing to report": {Report{}, nil},
		"disk below":        {Report{DiskTotal: 1000, DiskUsed: 899}, nil},
		"disk at limit":     {Report{DiskTotal: 1000, DiskUsed: 900}, []Warning{{WarnDiskFull, 90}}},
		"certificate fine":  {Report{Insight: Insight{CertExpires: at(31 * day)}}, nil},
		"certificate soon":  {Report{Insight: Insight{CertExpires: at(29*day + time.Hour)}}, []Warning{{WarnCertExpiring, 29}}},
		"certificate gone":  {Report{Insight: Insight{CertExpires: at(-3*day - time.Hour)}}, []Warning{{WarnCertExpiring, -3}}},
		"both": {
			Report{DiskTotal: 100, DiskUsed: 99, Insight: Insight{CertExpires: at(day)}},
			[]Warning{{WarnDiskFull, 99}, {WarnCertExpiring, 1}},
		},
	} {
		got := c.report.Warnings(now)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: got %v, want %v", name, got, c.want)
			}
		}
	}
}

func TestLogsPayload(t *testing.T) {
	for payload, valid := range map[string]bool{
		`{}`:                  true,
		`{"lines":500}`:       true,
		`{"lines":501}`:       false,
		`{"lines":-1}`:        false,
		`{"unit":"sshd"}`:     false,
		`{"user":"anna"}`:     false,
		`{"args":["--user"]}`: false,
	} {
		if err := Validate(TaskLogsFetch, json.RawMessage(payload)); (err == nil) != valid {
			t.Errorf("%s: %v", payload, err)
		}
	}
}

func TestLogsNeedNoSignature(t *testing.T) {
	if NeedsSignature(TaskLogsFetch) {
		t.Error("logs.fetch should run without a signature")
	}
}

// Report embeds Insight, which must not nest in the JSON.
func TestInsightIsPartOfTheReport(t *testing.T) {
	raw, err := json.Marshal(Report{Insight: Insight{Updates: &UpdateStatus{Pending: 3}}})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["updates"]; !ok {
		t.Errorf("no updates in %s", raw)
	}
}
