package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func TestAgentIdentityMismatchDisablesHourlyButPreservesLegacyAndObligations(t *testing.T) {
	const currentID = "99999999999999999999999999999999"
	var path string
	var before []byte
	var expected protocol.HourlyCreditInstall
	f := prepareHourlyAgentFixture(t, true, false, func(dir string) {
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(state.Data{AgentID: currentID, Users: []protocol.User{}})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "state.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		path = filepath.Join(dir, "hourly-credits.json")
		store, err := hourly.OpenCreditStore(path)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		expected = protocol.HourlyCreditInstall{ReservationID: "old-agent-credit", IssueSequence: 1, Owner: protocol.HourlyOwner{ID: "account", Generation: 7}, DayUTC: time.Now().UTC().Format(time.DateOnly), AgentID: "11111111111111111111111111111111", BootID: "22222222222222222222222222222222", SessionID: "33333333333333333333333333333333", ByteCeiling: 1000, Kind: "free"}
		if _, err = store.SealAbsent(context.Background(), expected); err != nil {
			t.Fatal(err)
		}
		before, err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
	})
	peer := f.peer(t)
	var hello struct {
		AgentID      string   `json:"agent_id"`
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal(f.frame(t, peer, "agent.hello", "").Data, &hello); err != nil {
		t.Fatal(err)
	}
	if hello.AgentID != currentID || peer.session != "" || slices.Contains(hello.Capabilities, protocol.HourlyCapability) || f.a.checkHourlyHealth() {
		t.Fatal("different state identity advertised retained credit as usable")
	}
	f.config.Users[0].Hourly = nil
	f.apply(t, peer)
	if !f.a.Runtime.Ready() || f.a.Store.Metadata().ConfigRevision != 1 {
		t.Fatal("hourly identity mismatch stopped legacy activation")
	}
	proofs := f.a.hourly.store.Recovery()
	if len(proofs) != 1 || proofs[0].Install != expected || proofs[0].UnusedBytes != expected.ByteCeiling {
		t.Fatal("identity mismatch changed retained financial evidence", proofs)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("identity mismatch rewrote the old-agent journal", err)
	}
}
