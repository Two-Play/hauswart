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

	"github.com/philippe/hauswart/internal/api"
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
	// One connection serialises writes, which is plenty at family scale and
	// makes the claim-a-task transaction trivially safe.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

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
	hash      string
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
		`SELECT id, username, linux_user, role, password_hash FROM users WHERE username = ?`, username).
		Scan(&u.ID, &u.Username, &u.LinuxUser, &u.Role, &u.hash)
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
		AND (role != 'admin' OR (SELECT COUNT(*) FROM users WHERE role = 'admin') > 1)`, id)
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
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, linux_user, role FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.LinuxUser, &u.Role); err != nil {
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
		SELECT u.id, u.username, u.linux_user, u.role FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ?`, hashToken(token), time.Now().Unix()).
		Scan(&u.ID, &u.Username, &u.LinuxUser, &u.Role)
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
	var want string
	err := s.db.QueryRowContext(ctx, `SELECT revoked, cert_serial FROM devices WHERE id = ?`, id).Scan(&revoked, &want)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !revoked && want == serial, nil
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

// ClaimTask atomically moves the oldest pending task to running.
func (s *Store) ClaimTask(ctx context.Context, deviceID string) (*api.Task, error) {
	var t api.Task
	var payload string
	err := s.db.QueryRowContext(ctx, `
		UPDATE tasks SET status = 'running', claimed_at = ?
		WHERE id = (SELECT id FROM tasks WHERE device_id = ? AND status = 'pending' ORDER BY created_at, rowid LIMIT 1)
		RETURNING id, type, payload`, time.Now().Unix(), deviceID).Scan(&t.ID, &t.Type, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.Payload = json.RawMessage(payload)
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
		UPDATE tasks SET status = ?, output = ?, finished_at = ?,
			payload = CASE WHEN type = ? THEN '{}' ELSE payload END
		WHERE id = ? AND device_id = ? AND status = 'running'`,
		status, r.Output, time.Now().Unix(), api.TaskUserPassword, taskID, deviceID)
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
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now.Unix()); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM enroll_tokens WHERE expires_at <= ?`, now.Unix()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE tasks SET status = 'failed', output = 'no result from agent', finished_at = ?,
			payload = CASE WHEN type = ? THEN '{}' ELSE payload END
		WHERE status = 'running' AND claimed_at < ?`, now.Unix(), api.TaskUserPassword, now.Add(-staleAfter).Unix())
	return err
}

func (s *Store) ListTasks(ctx context.Context, limit int) ([]TaskRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, device_id, type, payload, status, output, created_by, created_at, finished_at
		FROM tasks ORDER BY created_at DESC, rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tasks := []TaskRow{}
	for rows.Next() {
		var t TaskRow
		var payload string
		if err := rows.Scan(&t.ID, &t.DeviceID, &t.Type, &payload, &t.Status, &t.Output, &t.CreatedBy, &t.CreatedAt, &t.FinishedAt); err != nil {
			return nil, err
		}
		t.Payload = json.RawMessage(payload)
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
