package update

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func TestBinaryCompatibilityRetainsEveryHourlyPolicySnapshot(t *testing.T) {
	for _, location := range []string{"authorization", "accepted", "staged"} {
		t.Run(location, func(t *testing.T) {
			dir := t.TempDir()
			users := []protocol.User{{ID: 1, Hourly: &protocol.HourlyUser{Owner: protocol.HourlyOwner{ID: "owner", Generation: 1}, EnrollmentID: "enrollment"}}}
			data := state.Data{AgentID: "fixture"}
			switch location {
			case "authorization":
				data.Users = users
			case "accepted":
				data.Config = &protocol.Config{Users: users}
			case "staged":
				data.DesiredConfig = &protocol.Config{Users: users}
			}
			raw, err := json.Marshal(data)
			if err != nil {
				t.Fatal(err)
			}
			if err = state.AtomicWrite(filepath.Join(dir, "state.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			assertHourlyCompatibilityRequired(t, &Manager{Dir: filepath.Join(dir, "updates")})
		})
	}
}

func TestRetainedCreditJournalBlocksIncompatibleRollbackWithoutOrdinaryState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(dir, "hourly-credits.json")
	store, err := hourly.OpenCreditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	m := &Manager{Dir: filepath.Join(dir, "updates")}
	if err = m.checkCapabilities([]byte(`{"capabilities":[]}`)); err != nil {
		t.Fatal("pristine journal prevented first-upgrade rollback", err)
	}
	_, err = store.Install(context.Background(), protocol.HourlyCreditInstall{
		ReservationID: "retained", IssueSequence: 1, Owner: protocol.HourlyOwner{ID: "owner", Generation: 1},
		DayUTC: "2026-11-09", AgentID: "11111111111111111111111111111111", BootID: "22222222222222222222222222222222",
		SessionID: "33333333333333333333333333333333", ByteCeiling: 1000, Kind: "free",
	})
	if err != nil {
		t.Fatal(err)
	}
	assertHourlyCompatibilityRequired(t, m)
	// The old binary is inspected before either member of the installed pair moves.
	tx := transactionFixture(dir)
	for _, target := range []string{tx.NodePath, tx.CLIPath} {
		if err = os.WriteFile(target, []byte("current binary"), 0755); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(target+".old", []byte("previous binary"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	m.Runner = hourlyMetadataRunner{t: t, target: tx.NodePath + ".old"}
	if err = m.restore(context.Background(), &tx); err == nil {
		t.Fatal("rollback accepted a binary unable to recover retained credit")
	}
	for _, target := range []string{tx.NodePath, tx.CLIPath} {
		raw, err := os.ReadFile(target)
		if err != nil || string(raw) != "current binary" {
			t.Fatal("incompatible rollback replaced a live binary", target, err)
		}
	}
	corrupt := `{"version":1,"high_water":"1"}`
	if err = os.WriteFile(path, []byte(corrupt), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = m.requiredCapabilities(); err == nil {
		t.Fatal("corrupt hourly evidence enabled downgrade")
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != corrupt {
		t.Fatal("inspection rewrote corrupt financial evidence", err)
	}
	if tx.Status != "pending" {
		t.Fatal("rollback mutated its pending transaction")
	}
}

type hourlyMetadataRunner struct {
	t      *testing.T
	target string
}

func (r hourlyMetadataRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.t.Helper()
	if name != r.target || !slices.Equal(args, []string{"--version"}) {
		r.t.Fatal("unexpected host mutation", name, args)
	}
	return []byte(`{"capabilities":[]}`), nil
}

func assertHourlyCompatibilityRequired(t *testing.T, m *Manager) {
	t.Helper()
	required, err := m.requiredCapabilities()
	if err != nil || !slices.Contains(required, protocol.HourlyCapability) {
		t.Fatal("hourly evidence omitted from compatibility requirements", required, err)
	}
	metadata, err := json.Marshal(map[string]any{"capabilities": required})
	if err != nil || m.checkCapabilities(metadata) != nil {
		t.Fatal("compatible binary rejected", err)
	}
	filtered := slices.DeleteFunc(required, func(capability string) bool { return capability == protocol.HourlyCapability })
	metadata, err = json.Marshal(map[string]any{"capabilities": filtered})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.checkCapabilities(metadata); err == nil {
		t.Fatal("binary without hourly format support accepted")
	}
}
