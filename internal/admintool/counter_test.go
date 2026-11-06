package admintool

import (
	"crypto/ed25519"
	"crypto/rand"
	"math"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/sign"
)

func TestNextCounter(t *testing.T) {
	tests := []struct {
		name   string
		local  uint64
		report *api.Report
		want   uint64
	}{
		{"no report", 7, nil, 8},
		{"report behind", 7, &api.Report{Counter: 3}, 8},
		{"report equal", 7, &api.Report{Counter: 7}, 8},
		{"second admin computer signed", 7, &api.Report{Counter: 40}, 41},
		{"new admin.json", 0, &api.Report{Counter: 500}, 501},
		{"exactly at the limit", 7, &api.Report{Counter: 7 + maxCounterJump}, 8 + maxCounterJump},
		{"last counter", math.MaxUint64 - 1, nil, math.MaxUint64},
		{"last counter reported", math.MaxUint64 - 2, &api.Report{Counter: math.MaxUint64 - 1}, math.MaxUint64},
		{"huge report behind", math.MaxUint64 - 1, &api.Report{Counter: 1}, math.MaxUint64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nextCounter(tt.local, tt.report)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNextCounterRefuses(t *testing.T) {
	tests := []struct {
		name   string
		local  uint64
		report *api.Report
		want   string
	}{
		{"one above the limit", 7, &api.Report{Counter: 8 + maxCounterJump}, "refusing the counter"},
		{"wraps to zero", 7, &api.Report{Counter: math.MaxUint64}, "refusing the counter"},
		{"uses up the counter", 7, &api.Report{Counter: math.MaxUint64 - 1}, "refusing the counter"},
		{"wraps from a fresh start", 0, &api.Report{Counter: math.MaxUint64}, "refusing the counter"},
		{"reported within the limit, but the last one", math.MaxUint64 - 5, &api.Report{Counter: math.MaxUint64}, "used up"},
		{"local is the last one", math.MaxUint64, nil, "used up"},
		{"local is the last one, report behind", math.MaxUint64, &api.Report{Counter: 3}, "used up"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nextCounter(tt.local, tt.report)
			if err == nil {
				t.Fatalf("got %d, want an error", got)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %q, want %q in it", err, tt.want)
			}
		})
	}
}

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func sealConfig(t *testing.T, counter uint64) *config {
	t.Helper()
	t.Setenv("HAUSWART_ADMIN_DIR", t.TempDir())
	cfg := &config{Devices: map[string]*device{"id": {Name: "laptop", Counter: counter}}}
	if err := cfg.save(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func savedCounter(t *testing.T) uint64 {
	t.Helper()
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Devices["id"].Counter
}

func TestSealFollowsADeviceThatIsAhead(t *testing.T) {
	cfg := sealConfig(t, 5)
	key := testSigner(t)
	signed, err := seal(cfg, key, "id", &api.Report{Counter: 40}, api.TaskUserPassword, []byte("{}"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	env, err := sign.Verify(signed, []ssh.PublicKey{key.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	if env.Counter != 41 {
		t.Fatalf("signed counter %d", env.Counter)
	}
	if got := savedCounter(t); got != 41 {
		t.Fatalf("saved counter %d", got)
	}
}

// A refused report must neither spend a signature nor touch the stored counter.
func TestSealRefusesABadCounterFromTheServer(t *testing.T) {
	for _, reported := range []uint64{math.MaxUint64, math.MaxUint64 - 1, 5 + maxCounterJump + 1} {
		cfg := sealConfig(t, 5)
		_, err := seal(cfg, testSigner(t), "id", &api.Report{Counter: reported}, api.TaskUserPassword, []byte("{}"), time.Now().Add(time.Hour))
		if err == nil {
			t.Fatalf("counter %d was accepted", reported)
		}
		if !strings.Contains(err.Error(), "laptop") {
			t.Fatalf("error does not name the device: %v", err)
		}
		if cfg.Devices["id"].Counter != 5 {
			t.Fatalf("counter in memory became %d", cfg.Devices["id"].Counter)
		}
		if got := savedCounter(t); got != 5 {
			t.Fatalf("saved counter became %d", got)
		}
	}
}
