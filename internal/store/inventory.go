package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

// maxSoftwareRows limits a search, which a short word can make very long.
const maxSoftwareRows = 2000

// StoredInventory is the inventory of a device, without its list of packages.
type StoredInventory struct {
	api.Inventory
	PackageCount int   `json:"package_count"`
	UpdatedAt    int64 `json:"updated_at"`
}

// SaveInventory replaces what a device said before, all at once.
func (s *Store) SaveInventory(ctx context.Context, id string, inventory api.Inventory) error {
	packages := inventory.Packages
	inventory.Packages = nil
	raw, err := json.Marshal(inventory)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO device_inventory (device_id, document, updated_at) VALUES (?,?,?)
		ON CONFLICT (device_id) DO UPDATE SET document = excluded.document, updated_at = excluded.updated_at`,
		id, string(raw), time.Now().Unix()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM device_packages WHERE device_id = ?`, id); err != nil {
		return err
	}
	insert, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO device_packages (device_id, kind, name, version) VALUES (?,?,?,?)`)
	if err != nil {
		return err
	}
	defer insert.Close()
	for _, pkg := range packages {
		if _, err := insert.ExecContext(ctx, id, pkg.Kind, pkg.Name, pkg.Version); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Inventories returns the inventory of every device that sent one.
func (s *Store) Inventories(ctx context.Context) (map[string]StoredInventory, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT i.device_id, i.document, i.updated_at,
			(SELECT COUNT(*) FROM device_packages p WHERE p.device_id = i.device_id)
		FROM device_inventory i`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := map[string]StoredInventory{}
	for rows.Next() {
		var id, raw string
		var stored StoredInventory
		if err := rows.Scan(&id, &raw, &stored.UpdatedAt, &stored.PackageCount); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &stored.Inventory); err != nil {
			return nil, err
		}
		found[id] = stored
	}
	return found, rows.Err()
}

// DevicePackages lists what one device has installed.
func (s *Store) DevicePackages(ctx context.Context, id string) ([]api.Package, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT kind, name, version FROM device_packages WHERE device_id = ? ORDER BY kind DESC, name`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	packages := []api.Package{}
	for rows.Next() {
		var pkg api.Package
		if err := rows.Scan(&pkg.Kind, &pkg.Name, &pkg.Version); err != nil {
			return nil, err
		}
		packages = append(packages, pkg)
	}
	return packages, rows.Err()
}

// SoftwareDevice is a device with a package.
type SoftwareDevice struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
}

// SoftwareEntry is one version of a package and where it is.
type SoftwareEntry struct {
	Kind    string           `json:"kind"`
	Name    string           `json:"name"`
	Version string           `json:"version"`
	Devices []SoftwareDevice `json:"devices"`
}

var likeEscape = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// FindSoftware searches package names on active devices. The second value says
// that there was more than fits.
func (s *Store) FindSoftware(ctx context.Context, query string) ([]SoftwareEntry, bool, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.kind, p.name, p.version, d.id, d.hostname
		FROM device_packages p JOIN devices d ON d.id = p.device_id
		WHERE d.revoked = 0 AND p.name LIKE ? ESCAPE '\'
		ORDER BY p.name, p.kind, p.version, d.hostname LIMIT ?`,
		"%"+likeEscape.Replace(query)+"%", maxSoftwareRows+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	entries := []SoftwareEntry{}
	count := 0
	for rows.Next() {
		if count++; count > maxSoftwareRows {
			return entries, true, rows.Err()
		}
		var entry SoftwareEntry
		var device SoftwareDevice
		if err := rows.Scan(&entry.Kind, &entry.Name, &entry.Version, &device.ID, &device.Hostname); err != nil {
			return nil, false, err
		}
		if last := len(entries) - 1; last >= 0 && entries[last].Kind == entry.Kind && entries[last].Name == entry.Name && entries[last].Version == entry.Version {
			entries[last].Devices = append(entries[last].Devices, device)
			continue
		}
		entry.Devices = []SoftwareDevice{device}
		entries = append(entries, entry)
	}
	return entries, false, rows.Err()
}

// SaveAsset keeps what people know about a device.
func (s *Store) SaveAsset(ctx context.Context, id string, asset api.Asset, by string) error {
	raw, err := json.Marshal(asset)
	if err != nil {
		return err
	}
	var known string
	err = s.db.QueryRowContext(ctx, `SELECT id FROM devices WHERE id = ?`, id).Scan(&known)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO device_assets (device_id, document, updated_by, updated_at) VALUES (?,?,?,?)
		ON CONFLICT (device_id) DO UPDATE SET document = excluded.document, updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
		id, string(raw), by, time.Now().Unix())
	return err
}

// Assets returns the entries of all devices that have one.
func (s *Store) Assets(ctx context.Context) (map[string]api.Asset, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT device_id, document FROM device_assets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := map[string]api.Asset{}
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		var asset api.Asset
		if err := json.Unmarshal([]byte(raw), &asset); err != nil {
			return nil, err
		}
		found[id] = asset
	}
	return found, rows.Err()
}
