package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Two-Play/hauswart/internal/pki"
	"github.com/Two-Play/hauswart/internal/store"
)

var ctx = context.Background()

func setup(t *testing.T) (string, *pki.CA, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.LoadOrCreate(filepath.Join(dir, pkiDir))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, dbFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.CreateUser(ctx, "anna", "anna", "hash", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDevice(ctx, "device", "laptop", "serial"); err != nil {
		t.Fatal(err)
	}
	return dir, ca, st
}

func TestRoundTrip(t *testing.T) {
	dir, ca, st := setup(t)
	var archive bytes.Buffer
	// The source store stays open, like a running server.
	if err := Create(ctx, dir, &archive); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, "later", "later", "hash", "member"); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(t.TempDir(), "restored")
	if err := Restore(target, &archive); err != nil {
		t.Fatal(err)
	}
	restored, err := store.Open(filepath.Join(target, dbFile))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if ok, err := restored.DeviceAuthorized(ctx, "device", "serial"); err != nil || !ok {
		t.Fatalf("device lost: %v %v", ok, err)
	}
	if _, err := restored.UserByName(ctx, "anna"); err != nil {
		t.Fatalf("user lost: %v", err)
	}
	if _, err := restored.UserByName(ctx, "later"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("backup is not a snapshot: %v", err)
	}
	restoredCA, err := pki.LoadOrCreate(filepath.Join(target, pkiDir))
	if err != nil {
		t.Fatal(err)
	}
	if restoredCA.Fingerprint() != ca.Fingerprint() {
		t.Fatal("CA changed, every device would be cut off")
	}
	info, err := os.Stat(filepath.Join(target, pkiDir, "ca-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("CA key mode %v", info.Mode().Perm())
	}
}

func TestRestoreRefusesExistingData(t *testing.T) {
	dir, _, _ := setup(t)
	var archive bytes.Buffer
	if err := Create(ctx, dir, &archive); err != nil {
		t.Fatal(err)
	}
	if err := Restore(dir, &archive); !errors.Is(err, ErrNotEmpty) {
		t.Fatalf("got %v", err)
	}
}

func crafted(t *testing.T, header tar.Header) *bytes.Buffer {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	header.ModTime = time.Now()
	if err := tw.WriteHeader(&header); err != nil {
		t.Fatal(err)
	}
	if header.Size > 0 {
		if _, err := tw.Write(make([]byte, header.Size)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	return &out
}

func TestRestoreRejectsCraftedArchives(t *testing.T) {
	cases := map[string]tar.Header{
		"traversal":     {Name: "../evil", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644},
		"nested":        {Name: "pki/../../evil", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644},
		"absolute":      {Name: "/etc/passwd", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644},
		"unknown":       {Name: "other", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644},
		"symlink":       {Name: "pki/ca.pem", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777},
		"no pki subdir": {Name: "pki/a/b", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644},
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			if err := Restore(filepath.Join(parent, "data"), crafted(t, header)); err == nil {
				t.Fatal("accepted")
			}
			if _, err := os.Stat(filepath.Join(parent, "evil")); err == nil {
				t.Fatal("wrote outside the data directory")
			}
		})
	}
}

func TestRestoreRejectsArchiveWithoutDatabase(t *testing.T) {
	archive := crafted(t, tar.Header{Name: "pki/ca.pem", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644})
	if err := Restore(filepath.Join(t.TempDir(), "data"), archive); err == nil {
		t.Fatal("accepted")
	}
}
