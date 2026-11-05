// Package backup writes and restores everything the server cannot rebuild:
// the database and the certificate authority.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/philippe/hauswart/internal/store"
)

const (
	dbFile = "hauswart.db"
	pkiDir = "pki"
)

// ErrNotEmpty protects a live installation from being overwritten.
var ErrNotEmpty = errors.New("data directory already holds a database")

// Create writes an archive of dataDir to out. It is safe while the server
// runs: the database is copied through SQLite, not as a file, so the archive
// holds a consistent state even during writes.
func Create(ctx context.Context, dataDir string, out io.Writer) error {
	tmp, err := os.MkdirTemp("", "hauswart-backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	st, err := store.Open(filepath.Join(dataDir, dbFile))
	if err != nil {
		return err
	}
	snapshot := filepath.Join(tmp, dbFile)
	err = st.Snapshot(ctx, snapshot)
	st.Close()
	if err != nil {
		return fmt.Errorf("database snapshot: %w", err)
	}

	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	if err := addFile(tw, snapshot, dbFile); err != nil {
		return err
	}
	root := filepath.Join(dataDir, pkiDir)
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		return addFile(tw, p, pkiDir+"/"+d.Name())
	})
	if err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func addFile(tw *tar.Writer, src, name string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	err = tw.WriteHeader(&tar.Header{
		Name:    name,
		Mode:    int64(info.Mode().Perm()),
		Size:    info.Size(),
		ModTime: time.Now(),
	})
	if err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

// Restore unpacks an archive into dataDir, which must not hold a database.
func Restore(dataDir string, in io.Reader) error {
	if _, err := os.Stat(filepath.Join(dataDir, dbFile)); err == nil {
		return ErrNotEmpty
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dataDir, pkiDir), 0o700); err != nil {
		return err
	}
	gz, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	restored := false
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if !allowed(header) {
			return fmt.Errorf("unexpected entry %q in backup", header.Name)
		}
		target := filepath.Join(dataDir, filepath.FromSlash(header.Name))
		if err := writeFile(target, tr, os.FileMode(header.Mode).Perm()); err != nil {
			return err
		}
		restored = restored || header.Name == dbFile
	}
	if !restored {
		return errors.New("backup holds no database")
	}
	return nil
}

// allowed accepts exactly the entries Create writes. An archive is outside
// data, so a crafted one must not be able to write anywhere else.
func allowed(h *tar.Header) bool {
	if h.Typeflag != tar.TypeReg {
		return false
	}
	if h.Name == dbFile {
		return true
	}
	dir, base := path.Split(h.Name)
	return dir == pkiDir+"/" && base != "" && !strings.ContainsAny(base, `/\`) && base != ".."
}

func writeFile(target string, r io.Reader, mode os.FileMode) error {
	tmp := target + ".restoring"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}
