package store

import (
	"context"
	"errors"
	"strings"
)

// Group is a named set of devices.
type Group struct {
	ID      int64    `json:"id"`
	Name    string   `json:"name"`
	Devices []string `json:"devices"`
}

// ErrGroupExists reports a name that is already taken.
var ErrGroupExists = errors.New("group exists")

func (s *Store) CreateGroup(ctx context.Context, name string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO device_groups (name) VALUES (?)`, name)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, ErrGroupExists
		}
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) DeleteGroup(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM device_groups WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetGroupDevices replaces a group's members. Revoked devices can stay
// members, they simply no longer pick up tasks.
func (s *Store) SetGroupDevices(ctx context.Context, id int64, devices []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM device_groups WHERE id = ?)`, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM group_devices WHERE group_id = ?`, id); err != nil {
		return err
	}
	for _, device := range devices {
		if _, err := tx.ExecContext(ctx, `INSERT INTO group_devices (group_id, device_id) VALUES (?,?)`, id, device); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT g.id, g.name, COALESCE(m.device_id, '')
		FROM device_groups g LEFT JOIN group_devices m ON m.group_id = g.id
		ORDER BY g.name, m.device_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := []Group{}
	for rows.Next() {
		var id int64
		var name, device string
		if err := rows.Scan(&id, &name, &device); err != nil {
			return nil, err
		}
		if len(groups) == 0 || groups[len(groups)-1].ID != id {
			groups = append(groups, Group{ID: id, Name: name, Devices: []string{}})
		}
		if device != "" {
			last := &groups[len(groups)-1]
			last.Devices = append(last.Devices, device)
		}
	}
	return groups, rows.Err()
}

// GroupDevices lists the members that can still receive tasks.
func (s *Store) GroupDevices(ctx context.Context, id int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT m.device_id FROM group_devices m JOIN devices d ON d.id = m.device_id
		WHERE m.group_id = ? AND d.revoked = 0 ORDER BY m.device_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices := []string{}
	for rows.Next() {
		var device string
		if err := rows.Scan(&device); err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, rows.Err()
}
