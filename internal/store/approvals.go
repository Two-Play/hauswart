package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

// SetGroupApprovals stores a group's approval rules, and empty rules remove
// them. A group that does not exist fails on the foreign key.
func (s *Store) SetGroupApprovals(ctx context.Context, group int64, rules api.ApprovalRules, by string) error {
	if rules.IsZero() {
		var exists bool
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM device_groups WHERE id = ?)`, group).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		_, err := s.db.ExecContext(ctx, `DELETE FROM group_approvals WHERE group_id = ?`, group)
		return err
	}
	document, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO group_approvals (group_id, document, updated_by, updated_at) VALUES (?,?,?,?)
		ON CONFLICT (group_id) DO UPDATE SET document = excluded.document,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
		group, string(document), by, time.Now().Unix())
	return err
}

// GroupApprovals returns a group's approval rules, empty if it has none.
func (s *Store) GroupApprovals(ctx context.Context, group int64) (api.ApprovalRules, error) {
	return s.approvalRow(ctx, `SELECT document FROM group_approvals WHERE group_id = ?`, group)
}

// SetDefaultApprovals stores the rules of devices without rules of their own.
func (s *Store) SetDefaultApprovals(ctx context.Context, rules api.ApprovalRules, by string) error {
	document, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO default_approvals (id, document, updated_by, updated_at) VALUES (1,?,?,?)
		ON CONFLICT (id) DO UPDATE SET document = excluded.document,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
		string(document), by, time.Now().Unix())
	return err
}

// DefaultApprovals returns the default approval rules, empty if none were set.
func (s *Store) DefaultApprovals(ctx context.Context) (api.ApprovalRules, error) {
	return s.approvalRow(ctx, `SELECT document FROM default_approvals WHERE id = 1`)
}

func (s *Store) approvalRow(ctx context.Context, query string, args ...any) (api.ApprovalRules, error) {
	var rules api.ApprovalRules
	var document string
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return rules, nil
	}
	if err != nil {
		return rules, err
	}
	err = json.Unmarshal([]byte(document), &rules)
	return rules, err
}

// DeviceApprovals returns the approval rules of every group of a device. A
// group without rules counts too, as empty rules, so that it uses the defaults.
func (s *Store) DeviceApprovals(ctx context.Context, device string) ([]api.ApprovalRules, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT COALESCE(a.document, '{}') FROM group_devices m
		LEFT JOIN group_approvals a ON a.group_id = m.group_id
		WHERE m.device_id = ? ORDER BY m.group_id`, device)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []api.ApprovalRules{}
	for rows.Next() {
		var document string
		if err := rows.Scan(&document); err != nil {
			return nil, err
		}
		var rules api.ApprovalRules
		if err := json.Unmarshal([]byte(document), &rules); err != nil {
			return nil, err
		}
		list = append(list, rules)
	}
	return list, rows.Err()
}
