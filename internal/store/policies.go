package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/philippe/hauswart/internal/api"
)

// SetGroupPolicy stores what a group asks for. Nothing about it reaches a device
// before an admin has signed the result.
func (s *Store) SetGroupPolicy(ctx context.Context, group int64, document []byte, by string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO group_policies (group_id, document, updated_by, updated_at) VALUES (?,?,?,?)
		ON CONFLICT (group_id) DO UPDATE SET document = excluded.document,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
		group, string(document), by, time.Now().Unix())
	return err
}

func (s *Store) DeleteGroupPolicy(ctx context.Context, group int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM group_policies WHERE group_id = ?`, group)
	return err
}

// GroupPolicy returns a group's policy, or nil if it has none.
func (s *Store) GroupPolicy(ctx context.Context, group int64) (*api.Policy, error) {
	var document string
	err := s.db.QueryRowContext(ctx, `SELECT document FROM group_policies WHERE group_id = ?`, group).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var policy api.Policy
	if err := json.Unmarshal([]byte(document), &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

// DevicePolicies returns the policies of a device's groups, by group name.
func (s *Store) DevicePolicies(ctx context.Context, device string) (map[string]api.Policy, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT g.name, p.document FROM group_devices m
		JOIN device_groups g ON g.id = m.group_id
		JOIN group_policies p ON p.group_id = m.group_id
		WHERE m.device_id = ?`, device)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	policies := map[string]api.Policy{}
	for rows.Next() {
		var name, document string
		if err := rows.Scan(&name, &document); err != nil {
			return nil, err
		}
		var policy api.Policy
		if err := json.Unmarshal([]byte(document), &policy); err != nil {
			return nil, err
		}
		policies[name] = policy
	}
	return policies, rows.Err()
}

// PolicyTask is a policy task that has not finished yet.
type PolicyTask struct {
	Type    string
	Payload string
	Status  string
}

// OpenPolicyTask returns the newest unfinished policy task of a device, if any.
func (s *Store) OpenPolicyTask(ctx context.Context, device string) (*PolicyTask, error) {
	return s.policyTask(ctx, device, `status IN ('signing','pending','running')`)
}

// WaitingPolicyTask returns the policy task that waits for a signature.
func (s *Store) WaitingPolicyTask(ctx context.Context, device string) (*PolicyTask, error) {
	return s.policyTask(ctx, device, `status = 'signing'`)
}

// SignedPolicyTask returns the newest policy task that is signed and on its way.
// Nothing can stop that one any more, so it decides what the device will have.
func (s *Store) SignedPolicyTask(ctx context.Context, device string) (*PolicyTask, error) {
	return s.policyTask(ctx, device, `status IN ('pending','running')`)
}

func (s *Store) policyTask(ctx context.Context, device, condition string) (*PolicyTask, error) {
	var t PolicyTask
	err := s.db.QueryRowContext(ctx, `
		SELECT type, payload, status FROM tasks
		WHERE device_id = ? AND type IN (?, ?) AND `+condition+`
		ORDER BY created_at DESC, rowid DESC LIMIT 1`, device, api.TaskPolicySet, api.TaskPolicyClear).
		Scan(&t.Type, &t.Payload, &t.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &t, err
}

// DropWaitingPolicyTasks removes policy tasks nobody signed yet. They describe a
// state that no longer applies, and signing one would only cause confusion.
func (s *Store) DropWaitingPolicyTasks(ctx context.Context, device string) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM tasks WHERE device_id = ? AND type IN (?, ?) AND status = 'signing'`,
		device, api.TaskPolicySet, api.TaskPolicyClear)
	return err
}
