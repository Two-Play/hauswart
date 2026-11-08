package store

import (
	"context"
	"strings"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

// LinkCatalog points a device to a catalog that is already stored. It returns
// false if the catalog is not known, and the device then has to send it.
func (s *Store) LinkCatalog(ctx context.Context, device, hash string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO device_catalogs (device_id, hash, updated_at)
		SELECT ?, hash, ? FROM catalogs WHERE hash = ?
		ON CONFLICT (device_id) DO UPDATE SET hash = excluded.hash, updated_at = excluded.updated_at`,
		device, time.Now().Unix(), hash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	return true, s.dropUnusedCatalogs(ctx)
}

// SaveCatalog stores a checked catalog and points the device to it.
func (s *Store) SaveCatalog(ctx context.Context, device string, catalog api.PackageCatalog) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	res, err := tx.ExecContext(ctx, `INSERT INTO catalogs (hash, updated_at) VALUES (?,?) ON CONFLICT DO NOTHING`, catalog.Hash, now)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		insert, err := tx.PrepareContext(ctx, `INSERT INTO catalog_names (hash, name) VALUES (?,?)`)
		if err != nil {
			return err
		}
		defer insert.Close()
		for _, name := range catalog.Names {
			if _, err := insert.ExecContext(ctx, catalog.Hash, name); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO device_catalogs (device_id, hash, updated_at) VALUES (?,?,?)
		ON CONFLICT (device_id) DO UPDATE SET hash = excluded.hash, updated_at = excluded.updated_at`,
		device, catalog.Hash, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.dropUnusedCatalogs(ctx)
}

func (s *Store) dropUnusedCatalogs(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM catalogs WHERE hash NOT IN (SELECT hash FROM device_catalogs)`)
	return err
}

// Scope says whose packages a search looks at. Empty devices with All unset
// means nobody's.
type Scope struct {
	Devices []string
	All     bool
}

// SearchPackages finds package names that contain q, in the catalogs and
// installed packages of the devices in scope. Names that start with q come
// first, then shorter ones. Installed says that a device in scope has it.
func (s *Store) SearchPackages(ctx context.Context, scope Scope, kind, q string, limit int) ([]SearchHit, error) {
	if !scope.All && len(scope.Devices) == 0 {
		return []SearchHit{}, nil
	}
	pattern := "%" + likeEscape.Replace(q) + "%"
	prefix := likeEscape.Replace(q) + "%"
	devices, args := scopeFilter(scope)
	var query string
	var all []any
	if kind == api.SearchPackage {
		query = `
		WITH found(name, installed) AS (
			SELECT n.name, 0 FROM catalog_names n
			WHERE n.name LIKE ? ESCAPE '\' AND n.hash IN (SELECT hash FROM device_catalogs c WHERE ` + devices("c") + `)
			UNION ALL
			SELECT p.name, 1 FROM device_packages p
			WHERE p.kind = ? AND p.name LIKE ? ESCAPE '\' AND ` + devices("p") + `
		)
		SELECT name, MAX(installed) FROM found GROUP BY name
		ORDER BY name LIKE ? ESCAPE '\' DESC, length(name), name LIMIT ?`
		all = append(all, pattern)
		all = append(all, args...)
		all = append(all, api.PackageSystem, pattern)
		all = append(all, args...)
	} else {
		query = `
		SELECT p.name, 1 FROM device_packages p
		WHERE p.kind = ? AND p.name LIKE ? ESCAPE '\' AND ` + devices("p") + `
		GROUP BY p.name ORDER BY p.name LIKE ? ESCAPE '\' DESC, length(p.name), p.name LIMIT ?`
		all = append(all, api.PackageFlatpak, pattern)
		all = append(all, args...)
	}
	all = append(all, prefix, limit)
	rows, err := s.db.QueryContext(ctx, query, all...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hits := []SearchHit{}
	for rows.Next() {
		var hit SearchHit
		if err := rows.Scan(&hit.Name, &hit.Installed); err != nil {
			return nil, err
		}
		hits = append(hits, hit)
	}
	return hits, rows.Err()
}

// InstalledAmong says which of names a device in scope has installed.
func (s *Store) InstalledAmong(ctx context.Context, scope Scope, kind string, names []string) (map[string]bool, error) {
	found := map[string]bool{}
	if len(names) == 0 || !scope.All && len(scope.Devices) == 0 {
		return found, nil
	}
	devices, args := scopeFilter(scope)
	query := `SELECT DISTINCT p.name FROM device_packages p WHERE p.kind = ? AND p.name IN (?` +
		strings.Repeat(",?", len(names)-1) + `) AND ` + devices("p")
	all := []any{kind}
	for _, name := range names {
		all = append(all, name)
	}
	all = append(all, args...)
	rows, err := s.db.QueryContext(ctx, query, all...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		found[name] = true
	}
	return found, rows.Err()
}

// SearchHit is a package name found in a search.
type SearchHit struct {
	Name      string
	Installed bool
}

// scopeFilter returns a condition on the device_id column of a table alias.
func scopeFilter(scope Scope) (func(alias string) string, []any) {
	if scope.All {
		return func(string) string { return "1" }, nil
	}
	args := make([]any, len(scope.Devices))
	for i, device := range scope.Devices {
		args[i] = device
	}
	marks := "?" + strings.Repeat(",?", len(scope.Devices)-1)
	return func(alias string) string { return alias + ".device_id IN (" + marks + ")" }, args
}
