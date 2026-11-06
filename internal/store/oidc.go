package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// userSource is the column that says where an account is managed.
const userSource = `CASE WHEN oidc_subject = '' THEN '' ELSE 'authentik' END`

// noPassword is no valid bcrypt hash, so no password can ever match it.
const noPassword = "!"

// ErrNameTaken says that an account of the same name exists that is not the
// same person.
var ErrNameTaken = errors.New("user name taken")

// DirectoryUser is what the identity provider says about someone.
type DirectoryUser struct {
	Subject  string
	Username string
	Role     string
}

// SaveDirectoryUser creates or updates an account of the identity provider. It
// goes by the subject, and never takes over an account by its name: otherwise
// whoever may name themselves "admin" there would become the local admin here.
func (s *Store) SaveDirectoryUser(ctx context.Context, d DirectoryUser) (User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()

	var u User
	err = tx.QueryRowContext(ctx, `SELECT id, disabled FROM users WHERE oidc_subject = ?`, d.Subject).Scan(&u.ID, &u.Disabled)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, err := tx.ExecContext(ctx, `
			INSERT INTO users (username, linux_user, password_hash, role, oidc_subject, created_at)
			VALUES (?,?,?,?,?,?)`, d.Username, d.Username, noPassword, d.Role, d.Subject, time.Now().Unix())
		if err != nil {
			return User{}, nameTaken(err)
		}
		if u.ID, err = res.LastInsertId(); err != nil {
			return User{}, err
		}
	case err != nil:
		return User{}, err
	default:
		// A demotion must not leave nobody in charge, as in SetRole.
		_, err := tx.ExecContext(ctx, `
			UPDATE users SET username = ?, linux_user = ?, role = CASE
				WHEN role = 'admin' AND ? != 'admin' AND (SELECT COUNT(*) FROM users WHERE role = 'admin') <= 1 THEN role
				ELSE ? END
			WHERE id = ?`, d.Username, d.Username, d.Role, d.Role, u.ID)
		if err != nil {
			return User{}, nameTaken(err)
		}
	}
	err = tx.QueryRowContext(ctx, `SELECT username, linux_user, role FROM users WHERE id = ?`, u.ID).
		Scan(&u.Username, &u.LinuxUser, &u.Role)
	if err != nil {
		return User{}, err
	}
	u.Source = "authentik"
	return u, tx.Commit()
}

func nameTaken(err error) error {
	if err != nil && containsUnique(err) {
		return ErrNameTaken
	}
	return err
}

// SetDirectoryUserDisabled changes whether an account may log in. Disabling ends
// its sessions as well.
func (s *Store) SetDirectoryUserDisabled(ctx context.Context, subject string, disabled bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE users SET disabled = ? WHERE oidc_subject = ?`, disabled, subject); err != nil {
		return err
	}
	if disabled {
		_, err := tx.ExecContext(ctx, `
			DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE oidc_subject = ?)`, subject)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DirectorySubjects lists the accounts of the identity provider.
func (s *Store) DirectorySubjects(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT oidc_subject FROM users WHERE oidc_subject != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	subjects := []string{}
	for rows.Next() {
		var subject string
		if err := rows.Scan(&subject); err != nil {
			return nil, err
		}
		subjects = append(subjects, subject)
	}
	return subjects, rows.Err()
}

// UserSource says where an account is managed.
func (s *Store) UserSource(ctx context.Context, id int64) (string, error) {
	var source string
	err := s.db.QueryRowContext(ctx, `SELECT `+userSource+` FROM users WHERE id = ?`, id).Scan(&source)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return source, err
}

func containsUnique(err error) bool { return strings.Contains(err.Error(), "UNIQUE") }
