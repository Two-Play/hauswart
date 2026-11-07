package store

import (
	"context"
	"database/sql"
	"errors"
)

// Roles. These are checks of the server only: a hacked server ignores them, and
// only what is pinned on a device still holds.
const (
	RoleAdmin = "admin"
	// RoleApprover may approve, but not start anything.
	RoleApprover = "approver"
	RoleMember   = "member"
)

func ValidRole(role string) bool {
	return role == RoleAdmin || role == RoleApprover || role == RoleMember
}

// SetRole changes a role. A single statement decides, as in DeleteUser, so the
// last admin cannot be demoted by two people at the same moment.
func (s *Store) SetRole(ctx context.Context, id int64, role string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE users SET role = ? WHERE id = ?
		AND (role != 'admin' OR ? = 'admin' OR (SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0) > 1)`, role, id, role)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	var exists bool
	err = s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id = ?)`, id).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return ErrLastAdmin
	}
	return ErrNotFound
}

// UserDevices lists the devices assigned to a user.
func (s *Store) UserDevices(ctx context.Context, userID int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT device_id FROM device_members WHERE user_id = ? ORDER BY device_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		devices = append(devices, id)
	}
	return devices, rows.Err()
}

// SetUserDevices replaces what is assigned to a user.
func (s *Store) SetUserDevices(ctx context.Context, userID int64, devices []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id = ?)`, userID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM device_members WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, device := range devices {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO device_members (user_id, device_id) VALUES (?,?)`, userID, device); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeviceAllowed says whether a user may file requests for a device. Only members
// are limited, and an unknown device falls through to the error of the caller.
func (s *Store) DeviceAllowed(ctx context.Context, userID int64, deviceID string) (bool, error) {
	var role string
	err := s.db.QueryRowContext(ctx, `SELECT role FROM users WHERE id = ?`, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if role != RoleMember {
		return true, nil
	}
	var assigned bool
	err = s.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM device_members WHERE user_id = ? AND device_id = ?)`, userID, deviceID).Scan(&assigned)
	return assigned, err
}
