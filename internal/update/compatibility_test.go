package update

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func TestBinaryCompatibilityRetainsAccountingAndExpiry(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().UTC().Add(time.Hour)
	if err = store.Authorize([]protocol.User{{ID: 1, UUID: "credential", InboundTags: []string{"in"}, AccountingPeriod: "period", ValidUntil: &until}}, 1); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{Dir: filepath.Join(dir, "updates")}
	if err = manager.checkCapabilities([]byte(`{"version":"v1.0.0"}`)); err == nil {
		t.Fatal("incompatible binary accepted")
	}
	metadata, err := json.Marshal(map[string]any{"capabilities": []string{"traffic_periods_v1", "traffic_period_barriers_v1", "authorization_expiry", "volatile_connection_controls_v1"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.checkCapabilities(metadata); err != nil {
		t.Fatal(err)
	}
}

func TestBinaryDowngradeCannotLoseAuxiliaryListeners(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	config := protocol.Config{Xray: json.RawMessage(`{"inbounds":[{"tag":"utility","protocol":"tunnel"}]}`), Users: []protocol.User{}}
	if err = store.Authorize(config.Users, 1); err != nil {
		t.Fatal(err)
	}
	if err = store.Accept(config, 1); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{Dir: filepath.Join(dir, "updates")}
	if err = manager.checkCapabilities([]byte(`{"capabilities":[]}`)); err == nil {
		t.Fatal("downgrade lost a configured utility listener")
	}
	if err = manager.checkCapabilities([]byte(`{"capabilities":["native_auxiliary_inbounds_v1"]}`)); err != nil {
		t.Fatal(err)
	}
}
