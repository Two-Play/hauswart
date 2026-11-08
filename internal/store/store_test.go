package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/sign"
)

var ctx = context.Background()

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func device(t *testing.T, s *Store, id string) {
	t.Helper()
	if err := s.CreateDevice(ctx, id, "host-"+id, "serial-"+id); err != nil {
		t.Fatal(err)
	}
}

func TestSessionExpiry(t *testing.T) {
	s := open(t)
	id, err := s.CreateUser(ctx, "anna", "anna", "hash", "member")
	if err != nil {
		t.Fatal(err)
	}
	live, err := s.CreateSession(ctx, id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if u, err := s.SessionUser(ctx, live); err != nil || u.Username != "anna" {
		t.Fatalf("live session: %v %v", u, err)
	}
	expired, err := s.CreateSession(ctx, id, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionUser(ctx, expired); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session accepted: %v", err)
	}
	if err := s.DeleteSession(ctx, live); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionUser(ctx, live); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted session accepted: %v", err)
	}
}

func TestChangePasswordEndsOtherSessions(t *testing.T) {
	s := open(t)
	id, err := s.CreateUser(ctx, "anna", "anna", "old", "member")
	if err != nil {
		t.Fatal(err)
	}
	keep, _ := s.CreateSession(ctx, id, time.Hour)
	other, _ := s.CreateSession(ctx, id, time.Hour)
	if err := s.ChangePassword(ctx, id, "new", keep); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionUser(ctx, keep); err != nil {
		t.Fatalf("current session ended: %v", err)
	}
	if _, err := s.SessionUser(ctx, other); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other session survived: %v", err)
	}
	if hash, _ := s.UserPasswordHash(ctx, id); hash != "new" {
		t.Fatalf("hash %q", hash)
	}
}

func TestDeleteUserKeepsLastAdmin(t *testing.T) {
	s := open(t)
	first, _ := s.CreateUser(ctx, "a", "a", "h", "admin")
	second, _ := s.CreateUser(ctx, "b", "b", "h", "admin")
	member, _ := s.CreateUser(ctx, "c", "c", "h", "member")
	if err := s.DeleteUser(ctx, member); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, first); err != nil {
		t.Fatalf("second to last admin: %v", err)
	}
	if err := s.DeleteUser(ctx, second); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last admin: %v", err)
	}
	if err := s.DeleteUser(ctx, 999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestPasswordHashIsDroppedFromFinishedTasks(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	id, err := s.CreateTask(ctx, "a", api.TaskUserPassword, []byte(`{"hash":"secret"}`), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimTask(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishTask(ctx, "a", id, api.TaskResult{OK: true}); err != nil {
		t.Fatal(err)
	}
	tasks, _ := s.ListTasks(ctx, 10)
	if string(tasks[0].Payload) != "{}" {
		t.Fatalf("hash kept: %s", tasks[0].Payload)
	}
}

func TestTokensAreStoredHashed(t *testing.T) {
	s := open(t)
	token, err := s.CreateEnrollToken(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM enroll_tokens WHERE token_hash = ?`, token).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("token stored in clear text")
	}
}

func TestEnrollTokenExpiry(t *testing.T) {
	s := open(t)
	token, err := s.CreateEnrollToken(ctx, -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ConsumeEnrollToken(ctx, token); err != nil || ok {
		t.Fatalf("expired token accepted: %v %v", ok, err)
	}
}

func TestDeviceAuthorized(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	cases := []struct {
		id, serial string
		want       bool
	}{
		{"a", "serial-a", true},
		{"a", "old-serial", false},
		{"unknown", "serial-a", false},
	}
	for _, c := range cases {
		if got, err := s.DeviceAuthorized(ctx, c.id, c.serial); err != nil || got != c.want {
			t.Errorf("%s/%s: got %v, %v", c.id, c.serial, got, err)
		}
	}
	if err := s.RevokeDevice(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.DeviceAuthorized(ctx, "a", "serial-a"); got {
		t.Error("revoked device authorized")
	}
	if err := s.RevokeDevice(ctx, "unknown"); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking unknown device: %v", err)
	}
}

func TestRenewalKeepsOldSerialUntilNewOneIsUsed(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	if err := s.SetNextSerial(ctx, "a", "renewed"); err != nil {
		t.Fatal(err)
	}
	// The response may have been lost, so the old certificate must still work.
	if ok, _ := s.DeviceAuthorized(ctx, "a", "serial-a"); !ok {
		t.Fatal("old serial refused before the new one was used")
	}
	if ok, _ := s.DeviceAuthorized(ctx, "a", "renewed"); !ok {
		t.Fatal("new serial refused")
	}
	if ok, _ := s.DeviceAuthorized(ctx, "a", "serial-a"); ok {
		t.Fatal("old serial still valid after the new one was used")
	}
	if ok, _ := s.DeviceAuthorized(ctx, "a", "renewed"); !ok {
		t.Fatal("new serial not kept")
	}
}

func TestRevokedDeviceCannotUseRenewedSerial(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	if err := s.SetNextSerial(ctx, "a", "renewed"); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeDevice(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.DeviceAuthorized(ctx, "a", "renewed"); ok {
		t.Fatal("revoked device authorized")
	}
}

func TestMigrationUpgradesOldDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Turn it back into a database from before the first migration.
	device(t, s, "a")
	member, err := s.CreateUser(ctx, "anna", "anna", "hash", "member")
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.CreateSession(ctx, member, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTask(ctx, "a", api.TaskPkgUpgrade, []byte(`{}`), "admin"); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`DROP INDEX users_oidc_subject`,
		`ALTER TABLE users DROP COLUMN oidc_subject`,
		`ALTER TABLE users DROP COLUMN disabled`,
		`DROP TABLE group_policies`,
		`DROP TABLE service_certs`,
		`ALTER TABLE devices DROP COLUMN next_serial`,
		`DROP TABLE device_samples`,
		`DROP TABLE group_devices`,
		`DROP TABLE device_groups`,
		`ALTER TABLE tasks DROP COLUMN data`,
		`ALTER TABLE tasks DROP COLUMN signed`,
		`DROP TABLE passkeys`,
		`DROP TABLE device_members`,
		`ALTER TABLE devices DROP COLUMN passkey_counter`,
		`ALTER TABLE tasks DROP COLUMN passkey_envelope`,
		`ALTER TABLE tasks DROP COLUMN passkey_counter`,
		`DROP TABLE device_inventory`,
		`DROP TABLE device_packages`,
		`DROP TABLE device_assets`,
		`DROP TABLE group_approvals`,
		`DROP TABLE default_approvals`,
		`DROP TABLE device_catalogs`,
		`DROP TABLE catalog_names`,
		`DROP TABLE catalogs`,
		`ALTER TABLE requests DROP COLUMN task_id`,
		`ALTER TABLE devices DROP COLUMN suspended`,
		`DROP TABLE device_tpm`,
		`PRAGMA user_version = 0`,
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	for i := range 2 { // a second open must not run the migration again
		s, err = Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := s.DeviceAuthorized(ctx, "a", "serial-a"); err != nil || !ok {
			t.Fatalf("device lost: %v %v", ok, err)
		}
		if tasks, err := s.ListTasks(ctx, 10); err != nil || len(tasks) != 1 {
			t.Fatalf("tasks lost: %v %v", tasks, err)
		}
		// Changing the roles must not cascade into what depends on users.
		if u, err := s.SessionUser(ctx, session); err != nil || u.Role != RoleMember {
			t.Fatalf("session lost: %+v %v", u, err)
		}
		if devices, err := s.UserDevices(ctx, member); err != nil || len(devices) != 1 {
			t.Fatalf("existing member lost the devices: %v %v", devices, err)
		}
		if _, err := s.CreateUser(ctx, fmt.Sprint("approver", i), "p", "hash", RoleApprover); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateUser(ctx, fmt.Sprint("nobody", i), "n", "hash", "owner"); err == nil {
			t.Fatal("unknown role stored")
		}
		s.Close()
	}
}

func TestSigningQueue(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	id, err := s.CreateSigningTask(ctx, "a", api.TaskPkgInstall, []byte(`{}`), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if task, err := s.ClaimTask(ctx, "a"); err != nil || task != nil {
		t.Fatalf("unsigned task reached the device: %+v %v", task, err)
	}
	queue, err := s.SigningQueue(ctx)
	if err != nil || len(queue) != 1 {
		t.Fatalf("queue: %v %v", queue, err)
	}
	signed := sign.Signed{Envelope: []byte("e"), Signature: []byte("s")}
	if got, err := s.AttachSignature(ctx, id, signed); err != nil || got != "a" {
		t.Fatalf("attach: %q %v", got, err)
	}
	if _, err := s.AttachSignature(ctx, id, signed); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second signature: %v", err)
	}
	task, err := s.ClaimTask(ctx, "a")
	if err != nil || task == nil || task.Signed == nil || string(task.Signed.Envelope) != "e" {
		t.Fatalf("claim: %+v %v", task, err)
	}
}

func TestRejectTask(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	id, _ := s.CreateSigningTask(ctx, "a", api.TaskPkgInstall, []byte(`{}`), "admin")
	if err := s.RejectTask(ctx, id, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.RejectTask(ctx, id, "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second reject: %v", err)
	}
	if task, _ := s.ClaimTask(ctx, "a"); task != nil {
		t.Fatal("rejected task reached the device")
	}
}

func TestSignedEnvelopeIsDroppedAfterFinish(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	id, err := s.CreateSignedTask(ctx, "a", api.TaskUserPassword, sign.Signed{Envelope: []byte("hash")}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimTask(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishTask(ctx, "a", id, api.TaskResult{OK: true}); err != nil {
		t.Fatal(err)
	}
	var signed string
	if err := s.db.QueryRow(`SELECT signed FROM tasks WHERE id = ?`, id).Scan(&signed); err != nil {
		t.Fatal(err)
	}
	if signed != "" {
		t.Fatalf("envelope kept: %q", signed)
	}
}

func TestClaimTaskOrderAndIsolation(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	device(t, s, "b")
	first, err := s.CreateTask(ctx, "a", api.TaskPkgUpgrade, []byte(`{}`), "admin")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.CreateTask(ctx, "a", api.TaskPkgUpgrade, []byte(`{}`), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if task, err := s.ClaimTask(ctx, "b"); err != nil || task != nil {
		t.Fatalf("device b got a task of device a: %v %v", task, err)
	}
	for _, want := range []string{first, second} {
		task, err := s.ClaimTask(ctx, "a")
		if err != nil || task == nil || task.ID != want {
			t.Fatalf("want %s, got %+v, %v", want, task, err)
		}
	}
	if task, err := s.ClaimTask(ctx, "a"); err != nil || task != nil {
		t.Fatalf("task claimed twice: %+v %v", task, err)
	}
}

func TestFinishTaskOnlyOnce(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	id, err := s.CreateTask(ctx, "a", api.TaskPkgUpgrade, []byte(`{}`), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinishTask(ctx, "a", id, api.TaskResult{OK: true}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("finished a task nobody claimed: %v", err)
	}
	if _, err := s.ClaimTask(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishTask(ctx, "a", id, api.TaskResult{OK: false, Output: "boom"}); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishTask(ctx, "a", id, api.TaskResult{OK: true}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("result overwritten: %v", err)
	}
	tasks, err := s.ListTasks(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if tasks[0].Status != "failed" || tasks[0].Output != "boom" {
		t.Fatalf("got %+v", tasks[0])
	}
}

func TestTaskResultKeepsStructuredData(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	id, err := s.CreateTask(ctx, "a", api.TaskPkgUpgrade, []byte(`{}`), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimTask(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishTask(ctx, "a", id, api.TaskResult{OK: true, Data: json.RawMessage(`{"n":1}`)}); err != nil {
		t.Fatal(err)
	}
	tasks, err := s.ListTasks(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if string(tasks[0].Data) != `{"n":1}` {
		t.Fatalf("got %s", tasks[0].Data)
	}
}

func TestCleanup(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	id, err := s.CreateTask(ctx, "a", api.TaskPkgUpgrade, []byte(`{}`), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimTask(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Cleanup(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	tasks, _ := s.ListTasks(ctx, 10)
	if tasks[0].Status != "running" {
		t.Fatalf("fresh task failed: %s", tasks[0].Status)
	}
	if _, err := s.db.Exec(`UPDATE tasks SET claimed_at = ? WHERE id = ?`, time.Now().Add(-2*time.Hour).Unix(), id); err != nil {
		t.Fatal(err)
	}
	if err := s.Cleanup(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	tasks, _ = s.ListTasks(ctx, 10)
	if tasks[0].Status != "failed" {
		t.Fatalf("stale task still %s", tasks[0].Status)
	}
}

func TestDecideRequestOnce(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	user, err := s.CreateUser(ctx, "anna", "anna", "hash", "member")
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.CreateRequest(ctx, user, "a", "software", "vim", "")
	if err != nil {
		t.Fatal(err)
	}
	if won, err := s.DecideRequest(ctx, id, "approved", "admin"); err != nil || !won {
		t.Fatalf("first decision: %v %v", won, err)
	}
	if won, err := s.DecideRequest(ctx, id, "denied", "other"); err != nil || won {
		t.Fatalf("second decision won: %v %v", won, err)
	}
	r, err := s.GetRequest(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "approved" || r.DecidedBy != "admin" {
		t.Fatalf("got %+v", r)
	}
}

func TestRequestForUnknownDeviceFails(t *testing.T) {
	s := open(t)
	user, err := s.CreateUser(ctx, "anna", "anna", "hash", "member")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRequest(ctx, user, "missing", "software", "vim", ""); err == nil {
		t.Fatal("foreign keys are not enforced")
	}
}

func TestSaveReportRoundTrip(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	if err := s.SaveReport(ctx, "a", api.Report{Hostname: "new-name", MemTotal: 42}); err != nil {
		t.Fatal(err)
	}
	devices, err := s.ListDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := devices[0]
	if got.Hostname != "new-name" || got.Report.MemTotal != 42 || got.LastSeen == 0 {
		raw, _ := json.Marshal(got)
		t.Fatalf("got %s", raw)
	}
}

// The role approver was called parent before. Those accounts keep their rights.
func TestMigrationRenamesParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "paul", "paul", "hash", RoleApprover); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "mia", "mia", "hash", RoleMember); err != nil {
		t.Fatal(err)
	}
	// Back to the column as the migration before left it.
	for _, stmt := range []string{
		`ALTER TABLE users ADD COLUMN role_old TEXT NOT NULL DEFAULT 'member' CHECK (role_old IN ('admin','parent','member'))`,
		`UPDATE users SET role_old = CASE role WHEN 'approver' THEN 'parent' ELSE role END`,
		`ALTER TABLE users DROP COLUMN role`,
		`ALTER TABLE users RENAME COLUMN role_old TO role`,
		`DROP TABLE group_approvals`,
		`DROP TABLE default_approvals`,
		`DROP TABLE device_catalogs`,
		`DROP TABLE catalog_names`,
		`DROP TABLE catalogs`,
		`ALTER TABLE requests DROP COLUMN task_id`,
		`ALTER TABLE devices DROP COLUMN suspended`,
		`DROP TABLE device_tpm`,
		fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations)-6),
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for name, want := range map[string]string{"paul": RoleApprover, "mia": RoleMember} {
		if u, err := s.UserByName(ctx, name); err != nil || u.Role != want {
			t.Errorf("%s: %+v %v", name, u, err)
		}
	}
	if _, err := s.CreateUser(ctx, "old", "o", "hash", "parent"); err == nil {
		t.Error("the old role is still accepted")
	}
}

func TestRequestStates(t *testing.T) {
	for _, c := range []struct{ decision, task, want string }{
		{"open", "", api.RequestOpen},
		{"denied", "", api.RequestDenied},
		{"approved", "signing", api.RequestSigning},
		{"approved", "pending", api.RequestRunning},
		{"approved", "running", api.RequestRunning},
		{"approved", "done", api.RequestDone},
		{"approved", "failed", api.RequestFailed},
		{"approved", "", api.RequestRunning},
	} {
		if got := requestState(c.decision, c.task); got != c.want {
			t.Errorf("%s/%s: got %s, want %s", c.decision, c.task, got, c.want)
		}
	}
}
