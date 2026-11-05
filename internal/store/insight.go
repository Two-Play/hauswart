package store

import (
	"context"
	"time"

	"github.com/philippe/hauswart/internal/api"
)

const (
	// SampleRetention is how long resource values are kept.
	SampleRetention = 7 * 24 * time.Hour
	// Logs may hold personal details, and nothing needs them once they were
	// read, so they do not stay in the database or in backups for long.
	logRetention = time.Hour
)

// Sample is one point of a resource history.
type Sample struct {
	Time      int64   `json:"ts"`
	Load1     float64 `json:"load1"`
	MemUsed   int64   `json:"mem_used"`
	MemTotal  int64   `json:"mem_total"`
	DiskUsed  int64   `json:"disk_used"`
	DiskTotal int64   `json:"disk_total"`
}

// AddSample records a report. There is one row per device and minute at most,
// so a device that reports too often cannot fill the database.
func (s *Store) AddSample(ctx context.Context, id string, at time.Time, r api.Report) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO device_samples (device_id, minute, load1, mem_used, mem_total, disk_used, disk_total)
		VALUES (?,?,?,?,?,?,?)`,
		id, at.Unix()/60, r.Load1, int64(r.MemUsed), int64(r.MemTotal), int64(r.DiskUsed), int64(r.DiskTotal))
	return err
}

// History returns the averages of a device since a time, one per step.
func (s *Store) History(ctx context.Context, id string, since time.Time, step time.Duration) ([]Sample, error) {
	minutes := max(int64(step/time.Minute), 1)
	rows, err := s.db.QueryContext(ctx, `
		SELECT minute / ?1 * ?1 * 60, AVG(load1), CAST(AVG(mem_used) AS INTEGER), MAX(mem_total),
			CAST(AVG(disk_used) AS INTEGER), MAX(disk_total)
		FROM device_samples WHERE device_id = ?2 AND minute >= ?3
		GROUP BY minute / ?1 ORDER BY 1`, minutes, id, since.Unix()/60)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	samples := []Sample{}
	for rows.Next() {
		var p Sample
		if err := rows.Scan(&p.Time, &p.Load1, &p.MemUsed, &p.MemTotal, &p.DiskUsed, &p.DiskTotal); err != nil {
			return nil, err
		}
		samples = append(samples, p)
	}
	return samples, rows.Err()
}

// GetTask returns one task, including a result that lists leave out.
func (s *Store) GetTask(ctx context.Context, id string) (TaskRow, error) {
	tasks, err := s.queryTasks(ctx, `
		SELECT id, device_id, type, payload, status, output, data, created_by, created_at, finished_at
		FROM tasks WHERE id = ?`, id)
	if err != nil {
		return TaskRow{}, err
	}
	if len(tasks) == 0 {
		return TaskRow{}, ErrNotFound
	}
	return tasks[0], nil
}

func (s *Store) pruneInsight(ctx context.Context, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM device_samples WHERE minute < ?`,
		now.Add(-SampleRetention).Unix()/60); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE tasks SET data = '' WHERE type = ? AND data != '' AND finished_at < ?`,
		api.TaskLogsFetch, now.Add(-logRetention).Unix())
	return err
}
