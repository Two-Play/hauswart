package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

// PasskeyTypes returns what the admins let a passkey approve, the default if
// they never chose.
func (s *Store) PasskeyTypes(ctx context.Context) ([]string, error) {
	types, _, err := s.ChosenPasskeyTypes(ctx)
	return types, err
}

// ChosenPasskeyTypes is PasskeyTypes, and whether the admins chose at all.
// Until they do, devices keep the list they have.
func (s *Store) ChosenPasskeyTypes(ctx context.Context) ([]string, bool, error) {
	var document string
	err := s.db.QueryRowContext(ctx, `SELECT document FROM passkey_settings WHERE id = 1`).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return api.SortedTypes(api.DefaultPasskeyTypes), false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var p api.PasskeyTypesPayload
	if err := json.Unmarshal([]byte(document), &p); err != nil {
		return nil, false, err
	}
	return append([]string{}, api.SortedTypes(p.Types)...), true, nil
}

// SetPasskeyTypes saves the admins' choice.
func (s *Store) SetPasskeyTypes(ctx context.Context, types []string, by string) error {
	document, err := json.Marshal(api.PasskeyTypesPayload{Types: append([]string{}, api.SortedTypes(types)...)})
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO passkey_settings (id, document, updated_by, updated_at) VALUES (1,?,?,?)
		ON CONFLICT (id) DO UPDATE SET document = excluded.document,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
		string(document), by, time.Now().Unix())
	return err
}

// LatestTask returns the newest task of a type on a device whose status is
// one of statuses, nil if there is none.
func (s *Store) LatestTask(ctx context.Context, device, taskType string, statuses ...string) (*PolicyTask, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT type, payload, status FROM tasks WHERE device_id = ? AND type = ?
		ORDER BY created_at DESC, rowid DESC`, device, taskType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t PolicyTask
		if err := rows.Scan(&t.Type, &t.Payload, &t.Status); err != nil {
			return nil, err
		}
		if slices.Contains(statuses, t.Status) {
			return &t, nil
		}
	}
	return nil, rows.Err()
}

// DropWaitingTasks removes tasks of a type that nobody signed yet.
func (s *Store) DropWaitingTasks(ctx context.Context, device, taskType string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM tasks WHERE device_id = ? AND type = ? AND status = 'signing'`, device, taskType)
	return err
}
