package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/sign"
)

// ErrStale says that a later approval went ahead of this one on the device.
var ErrStale = errors.New("stale approval")

// maxReportedCounter keeps a value a device reports inside what SQLite stores.
const maxReportedCounter = 1 << 62

// PasskeyRow is a registered passkey. On the server, it is only a candidate: it
// does nothing until an admin pins it on a device with a signed keys.set.
type PasskeyRow struct {
	ID           int64  `json:"id"`
	UserID       int64  `json:"user_id"`
	Username     string `json:"username"`
	Name         string `json:"name"`
	CredentialID []byte `json:"credential_id"`
	PublicKey    []byte `json:"public_key"`
	RPID         string `json:"rp_id"`
	Origin       string `json:"origin"`
	CreatedAt    int64  `json:"created_at"`
}

func (s *Store) CreatePasskey(ctx context.Context, userID int64, p sign.Passkey) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO passkeys (user_id, name, credential_id, public_key, rp_id, origin, created_at)
		VALUES (?,?,?,?,?,?,?)`, userID, p.Name, p.CredentialID, p.PublicKey, p.RPID, p.Origin, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListPasskeys returns all passkeys, or one user's when userID is not 0.
func (s *Store) ListPasskeys(ctx context.Context, userID int64) ([]PasskeyRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.id, p.user_id, u.username, p.name, p.credential_id, p.public_key, p.rp_id, p.origin, p.created_at
		FROM passkeys p JOIN users u ON u.id = p.user_id
		WHERE ? = 0 OR p.user_id = ? ORDER BY p.created_at, p.id`, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	passkeys := []PasskeyRow{}
	for rows.Next() {
		var p PasskeyRow
		if err := rows.Scan(&p.ID, &p.UserID, &p.Username, &p.Name, &p.CredentialID, &p.PublicKey, &p.RPID, &p.Origin, &p.CreatedAt); err != nil {
			return nil, err
		}
		passkeys = append(passkeys, p)
	}
	return passkeys, rows.Err()
}

// DeletePasskey removes a candidate, for one user unless userID is 0. A pin on a
// device stays, because only a signed keys.set reaches that.
func (s *Store) DeletePasskey(ctx context.Context, id, userID int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM passkeys WHERE id = ? AND (? = 0 OR user_id = ?)`, id, userID, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// WaitingRow is a task waiting for approval, with what a passkey needs.
type WaitingRow struct {
	TaskRow
	Hostname string `json:"hostname"`
	envelope []byte
}

// Envelope is the prepared envelope, empty if there is none yet.
func (w WaitingRow) Envelope() []byte { return w.envelope }

const waitingSelect = `
	SELECT t.id, t.device_id, t.type, t.payload, t.status, t.output, t.data, t.created_by, t.created_at, t.finished_at,
	       d.hostname, t.passkey_envelope
	FROM tasks t JOIN devices d ON d.id = t.device_id WHERE t.status = 'signing'`

func scanWaiting(row interface{ Scan(...any) error }) (WaitingRow, error) {
	var w WaitingRow
	var payload, data string
	err := row.Scan(&w.ID, &w.DeviceID, &w.Type, &payload, &w.Status, &w.Output, &data, &w.CreatedBy, &w.CreatedAt, &w.FinishedAt,
		&w.Hostname, &w.envelope)
	w.Payload = json.RawMessage(payload)
	w.fillExpiry()
	return w, err
}

// WaitingTask finds a task waiting for approval.
func (s *Store) WaitingTask(ctx context.Context, id string) (WaitingRow, error) {
	w, err := scanWaiting(s.db.QueryRowContext(ctx, waitingSelect+` AND t.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return w, ErrNotFound
	}
	return w, err
}

// PasskeyQueue lists the tasks a passkey could approve, oldest first. Anything
// else stays out of reach of approvers.
func (s *Store) PasskeyQueue(ctx context.Context) ([]WaitingRow, error) {
	rows, err := s.db.QueryContext(ctx, waitingSelect+` ORDER BY t.created_at, t.rowid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	queue := []WaitingRow{}
	for rows.Next() {
		w, err := scanWaiting(rows)
		if err != nil {
			return nil, err
		}
		if api.PasskeyEligible(w.Type) {
			queue = append(queue, w)
		}
	}
	return queue, rows.Err()
}

// NextPasskeyCounter hands out the next counter of a device, above whatever it
// reported. A skipped counter does no harm, one used twice would.
func (s *Store) NextPasskeyCounter(ctx context.Context, deviceID string, reported uint64) (uint64, error) {
	var next int64
	err := s.db.QueryRowContext(ctx, `
		UPDATE devices SET passkey_counter = MAX(passkey_counter, ?) + 1 WHERE id = ?
		RETURNING passkey_counter`, int64(min(reported, maxReportedCounter)), deviceID).Scan(&next)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return uint64(next), err
}

// SetPasskeyEnvelope remembers the envelope of a task. Asking again gets the same
// one, so that repeating the request does not use up counters.
func (s *Store) SetPasskeyEnvelope(ctx context.Context, taskID string, envelope []byte, counter uint64) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE tasks SET passkey_envelope = ?, passkey_counter = ? WHERE id = ? AND status = 'signing'`,
		envelope, int64(counter), taskID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ReleasePasskeyTask hands an approved task to its device. If a task with a later
// counter already went there, the device would refuse this one, so the envelope
// is dropped and the approver has to confirm a new one.
func (s *Store) ReleasePasskeyTask(ctx context.Context, taskID string, signed sign.Signed) (string, error) {
	raw, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var device string
	var counter int64
	err = tx.QueryRowContext(ctx, `SELECT device_id, passkey_counter FROM tasks WHERE id = ? AND status = 'signing'`, taskID).
		Scan(&device, &counter)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	var overtaken bool
	err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM tasks WHERE device_id = ? AND passkey_counter > ? AND status IN ('running','done','failed'))`,
		device, counter).Scan(&overtaken)
	if err != nil {
		return "", err
	}
	if overtaken {
		if _, err := tx.ExecContext(ctx, `UPDATE tasks SET passkey_envelope = '', passkey_counter = 0 WHERE id = ?`, taskID); err != nil {
			return "", err
		}
		if err := tx.Commit(); err != nil {
			return "", err
		}
		return "", ErrStale
	}
	if _, err := tx.ExecContext(ctx, `UPDATE tasks SET status = 'pending', signed = ? WHERE id = ?`, string(raw), taskID); err != nil {
		return "", err
	}
	return device, tx.Commit()
}
