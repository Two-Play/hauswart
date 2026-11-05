package store

import (
	"context"
	"strings"
	"time"
)

// ServiceCert records that a certificate exists. Its private key was handed
// out when it was made and is stored nowhere.
type ServiceCert struct {
	Serial    string   `json:"serial"`
	Names     []string `json:"names"`
	NotAfter  int64    `json:"not_after"`
	CreatedBy string   `json:"created_by"`
	CreatedAt int64    `json:"created_at"`
}

func (s *Store) AddServiceCert(ctx context.Context, serial string, names []string, notAfter time.Time, by string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO service_certs (serial, names, not_after, created_by, created_at) VALUES (?,?,?,?,?)`,
		serial, strings.Join(names, " "), notAfter.Unix(), by, time.Now().Unix())
	return err
}

// ListServiceCerts returns the certificates that run out first at the top.
func (s *Store) ListServiceCerts(ctx context.Context) ([]ServiceCert, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT serial, names, not_after, created_by, created_at FROM service_certs ORDER BY not_after, serial`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	certs := []ServiceCert{}
	for rows.Next() {
		var c ServiceCert
		var names string
		if err := rows.Scan(&c.Serial, &names, &c.NotAfter, &c.CreatedBy, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.Names = strings.Fields(names)
		certs = append(certs, c)
	}
	return certs, rows.Err()
}
