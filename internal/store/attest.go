package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

// TPMRecord is what the server knows about the TPM of a device.
type TPMRecord struct {
	// EK is the fingerprint of the endorsement key the device came with first.
	EK string `json:"ek"`
	// AKPublic is the attestation key the server trusts, in the TPM's encoding.
	AKPublic []byte `json:"ak_public"`
	// PendingEK and PendingAK are another TPM, which waits for an admin.
	PendingEK string           `json:"pending_ek,omitempty"`
	PendingAK []byte           `json:"pending_ak,omitempty"`
	Baseline  *api.BootState   `json:"baseline,omitempty"`
	Current   *api.BootState   `json:"current,omitempty"`
	Changes   []api.BootChange `json:"changes,omitempty"`
	LastAt    time.Time        `json:"last_at,omitzero"`
	// TLSKey is the fingerprint of the device's TLS key in the TPM, empty
	// while the key is a file.
	TLSKey string `json:"tls_key,omitempty"`
}

// TPM returns the record of a device, ErrNotFound if it has none.
func (s *Store) TPM(ctx context.Context, id string) (TPMRecord, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT document FROM device_tpm WHERE device_id = ?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return TPMRecord{}, ErrNotFound
	}
	if err != nil {
		return TPMRecord{}, err
	}
	var rec TPMRecord
	return rec, json.Unmarshal([]byte(raw), &rec)
}

// SaveTPM replaces the record of a device.
func (s *Store) SaveTPM(ctx context.Context, id string, rec TPMRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO device_tpm (device_id, document, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(device_id) DO UPDATE SET document = excluded.document, updated_at = excluded.updated_at`,
		id, string(raw), time.Now().Unix())
	return err
}

// TPMs returns the records of all devices that have one.
func (s *Store) TPMs(ctx context.Context) (map[string]TPMRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT device_id, document FROM device_tpm`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := map[string]TPMRecord{}
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		var rec TPMRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			return nil, err
		}
		found[id] = rec
	}
	return found, rows.Err()
}
