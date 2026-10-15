package firewall

import (
	"context"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type fakeRunner struct {
	mu               sync.Mutex
	calls            []string
	fail             string
	canceledRecovery bool
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if strings.Contains(call, "nft -f") && ctx.Err() != nil {
		f.canceledRecovery = true
		return nil, ctx.Err()
	}
	if f.fail != "" && strings.Contains(call, f.fail) {
		return nil, errors.New("injected failure")
	}
	if name == "sshd" {
		return []byte("port 2222\n"), nil
	}
	if name == "nft" && len(args) > 0 && args[0] == "list" {
		return []byte("table inet old { }\n"), nil
	}
	if name == "sysctl" {
		return []byte("0\n"), nil
	}
	return nil, nil
}
func (f *fakeRunner) log() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, "\n")
}

type fakeBackend struct {
	calls    int
	redirect bool
	dns      bool
	apply    func(context.Context) error
}

func (f *fakeBackend) Reconcile(ctx context.Context, _ protocol.FirewallPolicy, redirect bool, _ []int) error {
	f.calls++
	f.redirect = redirect
	if f.apply != nil {
		return f.apply(ctx)
	}
	return nil
}
func (f *fakeBackend) DNS(_ context.Context, on bool) error { f.dns = on; return nil }
func fixture(t *testing.T) (*Manager, *fakeRunner, *fakeBackend) {
	t.Helper()
	dir := t.TempDir()
	f := &fakeRunner{}
	b := &fakeBackend{}
	return &Manager{Dir: filepath.Join(dir, "firewall"), ConfigPath: filepath.Join(dir, "nftables.conf"), UnitPath: filepath.Join(dir, "systemd", "x-node-firewall.service"), Executable: "/usr/local/bin/xnodectl", Runner: f, Backend: b}, f, b
}
func policy() protocol.FirewallPolicy {
	return protocol.FirewallPolicy{Enabled: true, Protect: true, TCPPorts: []int{443}}
}
func applyFixture(t *testing.T, m *Manager) Pending {
	t.Helper()
	p, err := m.Apply(context.Background(), "request", policy(), false)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConfirmationAndRollback(t *testing.T) {
	for _, confirm := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "confirm"}[confirm], func(t *testing.T) {
			m, f, b := fixture(t)
			p := applyFixture(t, m)
			if b.calls != 1 || !strings.Contains(f.log(), "--on-active=45s") || !strings.Contains(f.log(), "--timer-property=AccuracySec=1s") {
				t.Fatal("missing native apply or independent watchdog")
			}
			if strings.Contains(f.log(), "candidate.nft") || strings.Contains(f.log(), "nft -c") {
				t.Fatal("script renderer remains in apply path")
			}
			if confirm {
				if err := m.Confirm(context.Background(), p.ID); err != nil {
					t.Fatal(err)
				}
			}
			before := f.log()
			if err := m.Rollback(context.Background()); err != nil {
				t.Fatal(err)
			}
			if confirm {
				if f.log() != before {
					t.Fatal("confirmed transaction rolled back")
				}
				raw, err := os.ReadFile(m.ConfigPath)
				if err != nil || string(raw) != bootConfig {
					t.Fatal("boot config is not native")
				}
			} else if !strings.Contains(f.log(), "rollback.nft") {
				t.Fatal("previous rules not restored")
			}
		})
	}
}
func TestIdempotencyAndCorruptState(t *testing.T) {
	m, _, b := fixture(t)
	p := applyFixture(t, m)
	again, err := m.Apply(context.Background(), p.ID, policy(), false)
	if err != nil || again.ID != p.ID || b.calls != 1 {
		t.Fatal("retry reapplied policy", err)
	}
	changed := policy()
	changed.UDPPorts = []int{53}
	if _, err = m.Apply(context.Background(), p.ID, changed, false); err == nil {
		t.Fatal("reused ID changed inputs")
	}
	if err = m.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(m.path(), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(context.Background(), "next", policy(), false); err == nil {
		t.Fatal("corruption treated as unmanaged")
	}
}
func TestCancellationRecoveryAndAtomicRejection(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancellation", true: "rejection"}[rejected], func(t *testing.T) {
			m, f, b := fixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			b.apply = func(context.Context) error {
				if rejected {
					return errors.Join(errUnchanged, errors.New("kernel rejected"))
				}
				cancel()
				return ctx.Err()
			}
			if _, err := m.Apply(ctx, "request", policy(), false); err == nil {
				t.Fatal("expected failure")
			}
			if f.canceledRecovery {
				t.Fatal("recovery inherited cancellation")
			}
			if strings.Contains(f.log(), "nft -f") == rejected {
				t.Fatal("wrong kernel recovery decision")
			}
			p, err := readRecord(m.path())
			expected := "rolled_back"
			if rejected {
				expected = "failed"
			}
			if err != nil || p.Status != expected {
				t.Fatal("transaction not recovered", err)
			}
		})
	}
}

func TestRejectedApplyCanRetrySameInputs(t *testing.T) {
	m, _, b := fixture(t)
	b.apply = func(context.Context) error { return errors.Join(errUnchanged, errors.New("transient kernel error")) }
	if _, err := m.Apply(context.Background(), "retry", policy(), false); err == nil {
		t.Fatal("failure ignored")
	}
	b.apply = nil
	if _, err := m.Apply(context.Background(), "retry", policy(), false); err != nil {
		t.Fatal("safe retry blocked", err)
	}
	if b.calls != 2 {
		t.Fatal("safe retry was not executed")
	}
}
