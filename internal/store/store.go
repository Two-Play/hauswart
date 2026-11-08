// Package store is the SQLite persistence layer.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/sign"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrLastAdmin = errors.New("last admin")
)

const schema = `
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	linux_user TEXT NOT NULL,
	password_hash TEXT NOT NULL,
	role TEXT NOT NULL CHECK (role IN ('admin','member')),
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS enroll_tokens (
	token_hash TEXT PRIMARY KEY,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
	id TEXT PRIMARY KEY,
	hostname TEXT NOT NULL,
	cert_serial TEXT NOT NULL,
	revoked INTEGER NOT NULL DEFAULT 0,
	enrolled_at INTEGER NOT NULL,
	last_seen INTEGER NOT NULL DEFAULT 0,
	report TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS tasks (
	id TEXT PRIMARY KEY,
	device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	type TEXT NOT NULL,
	payload TEXT NOT NULL,
	status TEXT NOT NULL CHECK (status IN ('pending','running','done','failed')),
	output TEXT NOT NULL DEFAULT '',
	created_by TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	claimed_at INTEGER NOT NULL DEFAULT 0,
	finished_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS tasks_device_status ON tasks(device_id, status);
CREATE TABLE IF NOT EXISTS requests (
	id TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	kind TEXT NOT NULL CHECK (kind IN ('software','flatpak','sudo')),
	detail TEXT NOT NULL,
	reason TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL CHECK (status IN ('open','approved','denied')),
	decided_by TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
	id INTEGER PRIMARY KEY,
	ts INTEGER NOT NULL,
	actor TEXT NOT NULL,
	action TEXT NOT NULL,
	detail TEXT NOT NULL
);
`

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection serialises writes, which is plenty at household scale and
	// makes the claim-a-task transaction trivially safe.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migration: %w", err)
	}
	return &Store{db: db}, nil
}

// migrations run once each, in order, on top of the base schema. Append only:
// an existing database or a restored backup may be at any earlier version.
var migrations = []string{
	`ALTER TABLE devices ADD COLUMN next_serial TEXT NOT NULL DEFAULT ''`,
	// SQLite cannot change a CHECK constraint, so the table is rebuilt.
	`CREATE TABLE tasks_new (
		id TEXT PRIMARY KEY,
		device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		type TEXT NOT NULL,
		payload TEXT NOT NULL,
		status TEXT NOT NULL CHECK (status IN ('signing','pending','running','done','failed')),
		output TEXT NOT NULL DEFAULT '',
		created_by TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		claimed_at INTEGER NOT NULL DEFAULT 0,
		finished_at INTEGER NOT NULL DEFAULT 0,
		signed TEXT NOT NULL DEFAULT ''
	);
	INSERT INTO tasks_new (id, device_id, type, payload, status, output, created_by, created_at, claimed_at, finished_at)
		SELECT id, device_id, type, payload, status, output, created_by, created_at, claimed_at, finished_at FROM tasks;
	DROP TABLE tasks;
	ALTER TABLE tasks_new RENAME TO tasks;
	CREATE INDEX tasks_device_status ON tasks(device_id, status);`,
	`ALTER TABLE tasks ADD COLUMN data TEXT NOT NULL DEFAULT ''`,
	`CREATE TABLE device_groups (
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL UNIQUE
	);
	CREATE TABLE group_devices (
		group_id INTEGER NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
		device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		PRIMARY KEY (group_id, device_id)
	);`,
	`CREATE TABLE device_samples (
		device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		minute INTEGER NOT NULL,
		load1 REAL NOT NULL,
		mem_used INTEGER NOT NULL,
		mem_total INTEGER NOT NULL,
		disk_used INTEGER NOT NULL,
		disk_total INTEGER NOT NULL,
		PRIMARY KEY (device_id, minute)
	) WITHOUT ROWID;`,
	`CREATE TABLE service_certs (
		serial TEXT PRIMARY KEY,
		names TEXT NOT NULL,
		not_after INTEGER NOT NULL,
		created_by TEXT NOT NULL,
		created_at INTEGER NOT NULL
	);`,
	// A new column instead of a rebuilt table: dropping users would run its
	// ON DELETE CASCADE into sessions and requests.
	`ALTER TABLE users ADD COLUMN role_new TEXT NOT NULL DEFAULT 'member' CHECK (role_new IN ('admin','parent','member'));
	UPDATE users SET role_new = role;
	ALTER TABLE users DROP COLUMN role;
	ALTER TABLE users RENAME COLUMN role_new TO role;`,
	// Members see only what is assigned to them. Until now they saw everything,
	// so nothing disappears for them through this update.
	`CREATE TABLE device_members (
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		PRIMARY KEY (user_id, device_id)
	);
	INSERT INTO device_members SELECT u.id, d.id FROM users u, devices d WHERE u.role = 'member';`,
	`CREATE TABLE passkeys (
		id INTEGER PRIMARY KEY,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		name TEXT NOT NULL,
		credential_id BLOB NOT NULL UNIQUE,
		public_key BLOB NOT NULL,
		rp_id TEXT NOT NULL,
		origin TEXT NOT NULL,
		created_at INTEGER NOT NULL
	);
	ALTER TABLE devices ADD COLUMN passkey_counter INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE tasks ADD COLUMN passkey_envelope BLOB NOT NULL DEFAULT '';
	ALTER TABLE tasks ADD COLUMN passkey_counter INTEGER NOT NULL DEFAULT 0;`,
	`CREATE TABLE group_policies (
		group_id INTEGER PRIMARY KEY REFERENCES device_groups(id) ON DELETE CASCADE,
		document TEXT NOT NULL,
		updated_by TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	);`,
	`ALTER TABLE users ADD COLUMN oidc_subject TEXT NOT NULL DEFAULT '';
	ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;
	CREATE UNIQUE INDEX users_oidc_subject ON users(oidc_subject) WHERE oidc_subject != '';`,
	// As with the roles: SQLite cannot change a CHECK constraint.
	`ALTER TABLE requests ADD COLUMN kind_new TEXT NOT NULL DEFAULT 'software' CHECK (kind_new IN ('software','flatpak','sudo','screen'));
	UPDATE requests SET kind_new = kind;
	ALTER TABLE requests DROP COLUMN kind;
	ALTER TABLE requests RENAME COLUMN kind_new TO kind;`,
	`CREATE TABLE device_inventory (
		device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
		document TEXT NOT NULL,
		updated_at INTEGER NOT NULL,
		package_hash TEXT NOT NULL,
		package_count INTEGER NOT NULL
	);
	CREATE TABLE device_packages (
		device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		kind TEXT NOT NULL,
		name TEXT NOT NULL,
		version TEXT NOT NULL,
		PRIMARY KEY (device_id, kind, name, version)
	);
	CREATE INDEX device_packages_name ON device_packages(name);
	CREATE TABLE device_assets (
		device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
		document TEXT NOT NULL,
		updated_by TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	);`,
	// parent became approver: Hauswart is for offices and shared PCs as well.
	`ALTER TABLE users ADD COLUMN role_new TEXT NOT NULL DEFAULT 'member' CHECK (role_new IN ('admin','approver','member'));
	UPDATE users SET role_new = CASE role WHEN 'parent' THEN 'approver' ELSE role END;
	ALTER TABLE users DROP COLUMN role;
	ALTER TABLE users RENAME COLUMN role_new TO role;`,
	// Approval rules stay on the server. The defaults are a single row.
	`CREATE TABLE group_approvals (
		group_id INTEGER PRIMARY KEY REFERENCES device_groups(id) ON DELETE CASCADE,
		document TEXT NOT NULL,
		updated_by TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	);
	CREATE TABLE default_approvals (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		document TEXT NOT NULL,
		updated_by TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	);`,
}

func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	for ; version < len(migrations); version++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err := tx.Exec(migrations[version]); err != nil {
			return err
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, version+1)); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

// Snapshot writes a consistent copy of the database to path, even while the
// server is writing to it.
func (s *Store) Snapshot(ctx context.Context, path string) error {
	_, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, path)
	return err
}

// RandomToken returns a 256-bit hex token.
func RandomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Tokens are stored hashed, so a leaked database cannot be replayed as
// sessions or enrollments.
func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// --- users and sessions ---

type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	LinuxUser string `json:"linux_user"`
	Role      string `json:"role"`
	// Source is empty for a local account and authentik for one that belongs to
	// the identity provider, where it is managed.
	Source   string `json:"source,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
	hash     string
}

func (u User) PasswordHash() string { return u.hash }

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) CreateUser(ctx context.Context, username, linuxUser, hash, role string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, linux_user, password_hash, role, created_at) VALUES (?,?,?,?,?)`,
		username, linuxUser, hash, role, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UserByName(ctx context.Context, username string) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, linux_user, role, password_hash, `+userSource+`, disabled FROM users WHERE username = ?`, username).
		Scan(&u.ID, &u.Username, &u.LinuxUser, &u.Role, &u.hash, &u.Source, &u.Disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

func (s *Store) UserPasswordHash(ctx context.Context, id int64) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id = ?`, id).Scan(&hash)
	return hash, err
}

// ChangePassword stores a new hash and ends every other session of the user,
// so a stolen session does not outlive the password it came from.
func (s *Store) ChangePassword(ctx context.Context, id int64, hash, keepSession string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, hash, id); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND token_hash != ?`, id, hashToken(keepSession))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteUser removes an account. A single statement decides, so two admins
// removing each other at the same moment cannot leave nobody in charge.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM users WHERE id = ?
		AND (role != 'admin' OR (SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0) > 1)`, id)
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

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, linux_user, role, `+userSource+`, disabled FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.LinuxUser, &u.Role, &u.Source, &u.Disabled); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) CreateSession(ctx context.Context, userID int64, ttl time.Duration) (string, error) {
	token := RandomToken()
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?,?,?)`,
		hashToken(token), userID, time.Now().Add(ttl).Unix())
	return token, err
}

func (s *Store) SessionUser(ctx context.Context, token string) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.username, u.linux_user, u.role, `+userSource+` FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ? AND u.disabled = 0`, hashToken(token), time.Now().Unix()).
		Scan(&u.ID, &u.Username, &u.LinuxUser, &u.Role, &u.Source)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, hashToken(token))
	return err
}

// --- enrollment ---

func (s *Store) CreateEnrollToken(ctx context.Context, ttl time.Duration) (string, error) {
	token := RandomToken()
	_, err := s.db.ExecContext(ctx, `INSERT INTO enroll_tokens (token_hash, expires_at) VALUES (?,?)`,
		hashToken(token), time.Now().Add(ttl).Unix())
	return token, err
}

// ConsumeEnrollToken deletes the token and reports whether it was valid, so
// each token works exactly once.
func (s *Store) ConsumeEnrollToken(ctx context.Context, token string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM enroll_tokens WHERE token_hash = ? AND expires_at > ?`,
		hashToken(token), time.Now().Unix())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// --- devices ---

type Device struct {
	ID       string      `json:"id"`
	Hostname string      `json:"hostname"`
	Revoked  bool        `json:"revoked"`
	LastSeen int64       `json:"last_seen"`
	Report   *api.Report `json:"report"`
	// Warnings is set for admins only, like the report it comes from.
	Warnings []api.Warning `json:"warnings,omitempty"`
	serial   string
}

func (s *Store) CreateDevice(ctx context.Context, id, hostname, serial string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO devices (id, hostname, cert_serial, enrolled_at) VALUES (?,?,?,?)`,
		id, hostname, serial, time.Now().Unix())
	return err
}

// DeviceAuthorized checks a presented client certificate against the device
// record. This is the revocation check: the TLS layer alone would keep
// accepting a revoked device's still-valid certificate.
func (s *Store) DeviceAuthorized(ctx context.Context, id, serial string) (bool, error) {
	var revoked bool
	var current, next string
	err := s.db.QueryRowContext(ctx, `SELECT revoked, cert_serial, next_serial FROM devices WHERE id = ?`, id).
		Scan(&revoked, &current, &next)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if revoked {
		return false, nil
	}
	if next != "" && serial == next {
		// The device proved it received the renewed certificate, so the old
		// one can stop working now and not any earlier.
		_, err := s.db.ExecContext(ctx, `UPDATE devices SET cert_serial = ?, next_serial = '' WHERE id = ?`, next, id)
		return err == nil, err
	}
	return serial == current, nil
}

// SetNextSerial records a renewed certificate. The current one stays valid
// until the device uses the new one: if the response gets lost on the way,
// the device simply tries again instead of being locked out.
func (s *Store) SetNextSerial(ctx context.Context, id, serial string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET next_serial = ? WHERE id = ?`, serial, id)
	return err
}

func (s *Store) SaveReport(ctx context.Context, id string, r api.Report) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE devices SET report = ?, hostname = ?, last_seen = ? WHERE id = ?`,
		string(raw), r.Hostname, time.Now().Unix(), id)
	return err
}

func (s *Store) TouchDevice(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET last_seen = ? WHERE id = ?`, time.Now().Unix(), id)
	return err
}

func (s *Store) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, hostname, revoked, last_seen, report FROM devices ORDER BY hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices := []Device{}
	for rows.Next() {
		var d Device
		var raw string
		if err := rows.Scan(&d.ID, &d.Hostname, &d.Revoked, &d.LastSeen, &raw); err != nil {
			return nil, err
		}
		d.Report = &api.Report{}
		if err := json.Unmarshal([]byte(raw), d.Report); err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

func (s *Store) RevokeDevice(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET revoked = 1 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- tasks ---

type TaskRow struct {
	ID         string          `json:"id"`
	DeviceID   string          `json:"device_id"`
	Type       string          `json:"type"`
	Payload    json.RawMessage `json:"payload"`
	Status     string          `json:"status"`
	Output     string          `json:"output"`
	Data       json.RawMessage `json:"data,omitempty"`
	CreatedBy  string          `json:"created_by"`
	CreatedAt  int64           `json:"created_at"`
	FinishedAt int64           `json:"finished_at"`
}

func (s *Store) CreateTask(ctx context.Context, deviceID, taskType string, payload []byte, createdBy string) (string, error) {
	id := RandomToken()[:32]
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tasks (id, device_id, type, payload, status, created_by, created_at)
		VALUES (?,?,?,?,'pending',?,?)`, id, deviceID, taskType, string(payload), createdBy, time.Now().Unix())
	return id, err
}

// CreateSigningTask queues a task that waits for an admin's signature.
func (s *Store) CreateSigningTask(ctx context.Context, deviceID, taskType string, payload []byte, createdBy string) (string, error) {
	id := RandomToken()[:32]
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tasks (id, device_id, type, payload, status, created_by, created_at)
		VALUES (?,?,?,?,'signing',?,?)`, id, deviceID, taskType, string(payload), createdBy, time.Now().Unix())
	return id, err
}

// CreateSignedTask stores a task the admin tool signed on its own. Its content
// is only in the envelope, because it may hold a password hash.
func (s *Store) CreateSignedTask(ctx context.Context, deviceID, taskType string, signed sign.Signed, createdBy string) (string, error) {
	raw, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	id := RandomToken()[:32]
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO tasks (id, device_id, type, payload, status, signed, created_by, created_at)
		VALUES (?,?,?,'{}','pending',?,?,?)`, id, deviceID, taskType, string(raw), createdBy, time.Now().Unix())
	return id, err
}

// AttachSignature releases a queued task to its device and returns the device.
func (s *Store) AttachSignature(ctx context.Context, taskID string, signed sign.Signed) (string, error) {
	raw, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	var device string
	err = s.db.QueryRowContext(ctx, `
		UPDATE tasks SET status = 'pending', signed = ?, passkey_envelope = '', passkey_counter = 0
		WHERE id = ? AND status = 'signing'
		RETURNING device_id`, string(raw), taskID).Scan(&device)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return device, err
}

// RejectTask closes a queued task an admin refused to sign.
func (s *Store) RejectTask(ctx context.Context, taskID, by string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE tasks SET status = 'failed', output = ?, finished_at = ?, passkey_counter = 0, passkey_envelope = ''
		WHERE id = ? AND status = 'signing'`, "rejected by "+by, time.Now().Unix(), taskID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SigningQueue lists the tasks waiting for a signature, oldest first.
func (s *Store) SigningQueue(ctx context.Context) ([]TaskRow, error) {
	return s.queryTasks(ctx, `
		SELECT id, device_id, type, payload, status, output, data, created_by, created_at, finished_at
		FROM tasks WHERE status = 'signing' ORDER BY created_at, rowid`)
}

// DeviceProtected reports whether a device says it requires signatures. A
// device that lies only makes its own tasks fail: it decides by itself.
func (s *Store) DeviceProtected(ctx context.Context, id string) (bool, error) {
	report, err := s.DeviceReport(ctx, id)
	if err != nil {
		return false, err
	}
	return report.Protected, nil
}

// DeviceReport returns what a device last said about itself.
func (s *Store) DeviceReport(ctx context.Context, id string) (*api.Report, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT report FROM devices WHERE id = ?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var report api.Report
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		return nil, err
	}
	return &report, nil
}

// ClaimTask atomically moves the oldest pending task to running.
func (s *Store) ClaimTask(ctx context.Context, deviceID string) (*api.Task, error) {
	var t api.Task
	var payload, signed string
	err := s.db.QueryRowContext(ctx, `
		UPDATE tasks SET status = 'running', claimed_at = ?
		WHERE id = (SELECT id FROM tasks WHERE device_id = ? AND status = 'pending' ORDER BY passkey_counter, created_at, rowid LIMIT 1)
		RETURNING id, type, payload, signed`, time.Now().Unix(), deviceID).Scan(&t.ID, &t.Type, &payload, &signed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.Payload = json.RawMessage(payload)
	if signed != "" {
		t.Signed = &sign.Signed{}
		if err := json.Unmarshal([]byte(signed), t.Signed); err != nil {
			return nil, err
		}
	}
	return &t, nil
}

// FinishTask records a result. The device_id condition stops one device from
// writing results for another device's task.
func (s *Store) FinishTask(ctx context.Context, deviceID, taskID string, r api.TaskResult) error {
	status := "failed"
	if r.OK {
		status = "done"
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE tasks SET status = ?, output = ?, data = ?, finished_at = ?, signed = '',
			payload = CASE WHEN type = ? THEN '{}' ELSE payload END
		WHERE id = ? AND device_id = ? AND status = 'running'`,
		status, r.Output, string(r.Data), time.Now().Unix(), api.TaskUserPassword, taskID, deviceID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Cleanup drops expired sessions and tokens, and fails tasks whose result
// never arrived. They are not retried, because whether they ran is unknown.
func (s *Store) Cleanup(ctx context.Context, staleAfter time.Duration) error {
	now := time.Now()
	if err := s.pruneInsight(ctx, now); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now.Unix()); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM enroll_tokens WHERE expires_at <= ?`, now.Unix()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE tasks SET status = 'failed', output = 'no result from agent', finished_at = ?, signed = '',
			payload = CASE WHEN type = ? THEN '{}' ELSE payload END
		WHERE status = 'running' AND claimed_at < ?`, now.Unix(), api.TaskUserPassword, now.Add(-staleAfter).Unix())
	return err
}

func (s *Store) ListTasks(ctx context.Context, limit int) ([]TaskRow, error) {
	return s.queryTasks(ctx, `
		SELECT id, device_id, type, payload, status, output, data, created_by, created_at, finished_at
		FROM tasks ORDER BY created_at DESC, rowid DESC LIMIT ?`, limit)
}

func (s *Store) queryTasks(ctx context.Context, query string, args ...any) ([]TaskRow, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tasks := []TaskRow{}
	for rows.Next() {
		var t TaskRow
		var payload, data string
		if err := rows.Scan(&t.ID, &t.DeviceID, &t.Type, &payload, &t.Status, &t.Output, &data, &t.CreatedBy, &t.CreatedAt, &t.FinishedAt); err != nil {
			return nil, err
		}
		t.Payload = json.RawMessage(payload)
		if data != "" {
			t.Data = json.RawMessage(data)
		}
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}

// --- requests ---

type Request struct {
	ID        string `json:"id"`
	UserID    int64  `json:"user_id"`
	Username  string `json:"username"`
	LinuxUser string `json:"linux_user"`
	DeviceID  string `json:"device_id"`
	Hostname  string `json:"hostname"`
	Kind      string `json:"kind"`
	Detail    string `json:"detail"`
	Reason    string `json:"reason"`
	Status    string `json:"status"`
	DecidedBy string `json:"decided_by"`
	CreatedAt int64  `json:"created_at"`
	// Mode says who decides an open request, by the rules of now. The server
	// fills it in, the database does not keep it.
	Mode string `json:"mode,omitempty"`
}

func (s *Store) CreateRequest(ctx context.Context, userID int64, deviceID, kind, detail, reason string) (string, error) {
	id := RandomToken()[:32]
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO requests (id, user_id, device_id, kind, detail, reason, status, created_at)
		VALUES (?,?,?,?,?,?,'open',?)`, id, userID, deviceID, kind, detail, reason, time.Now().Unix())
	return id, err
}

const requestSelect = `
	SELECT r.id, r.user_id, u.username, u.linux_user, r.device_id, d.hostname,
	       r.kind, r.detail, r.reason, r.status, r.decided_by, r.created_at
	FROM requests r JOIN users u ON u.id = r.user_id JOIN devices d ON d.id = r.device_id`

func scanRequest(row interface{ Scan(...any) error }) (Request, error) {
	var r Request
	err := row.Scan(&r.ID, &r.UserID, &r.Username, &r.LinuxUser, &r.DeviceID, &r.Hostname,
		&r.Kind, &r.Detail, &r.Reason, &r.Status, &r.DecidedBy, &r.CreatedAt)
	return r, err
}

// ListRequests returns all requests, or only one user's when userID is not 0.
func (s *Store) ListRequests(ctx context.Context, userID int64) ([]Request, error) {
	rows, err := s.db.QueryContext(ctx, requestSelect+`
		WHERE ? = 0 OR r.user_id = ? ORDER BY r.created_at DESC, r.rowid DESC LIMIT 200`, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	requests := []Request{}
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		requests = append(requests, r)
	}
	return requests, rows.Err()
}

func (s *Store) GetRequest(ctx context.Context, id string) (Request, error) {
	r, err := scanRequest(s.db.QueryRowContext(ctx, requestSelect+` WHERE r.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

// DecideRequest closes an open request. It returns false if someone else
// decided first, which prevents a double approval from creating two tasks.
func (s *Store) DecideRequest(ctx context.Context, id, status, decidedBy string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE requests SET status = ?, decided_by = ? WHERE id = ? AND status = 'open'`,
		status, decidedBy, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// --- audit ---

type AuditEntry struct {
	TS     int64  `json:"ts"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}

func (s *Store) Audit(ctx context.Context, actor, action, detail string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit (ts, actor, action, detail) VALUES (?,?,?,?)`,
		time.Now().Unix(), actor, action, detail)
	return err
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts, actor, action, detail FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.TS, &e.Actor, &e.Action, &e.Detail); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
