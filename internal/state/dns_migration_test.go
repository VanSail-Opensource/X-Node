package state

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestBootstrapNormalizesAcceptedAndStagedLegacyDNSWithoutStateRewrite(t *testing.T) {
	dir := t.TempDir()
	accepted := protocol.Config{Xray: json.RawMessage(`{"inbounds":[]}`), Users: []protocol.User{}, DNS: protocol.DNSPolicy{Mode: "smartdns", Redirect: true, Upstreams: []string{"203.0.113.53"}}}
	desired := protocol.Clone(accepted)
	desired.Xray = json.RawMessage(`{"inbounds":[],"dns":{"servers":["192.0.2.53"]}}`)
	data := Data{AgentID: "preserved-agent", Revision: 7, ConfigRevision: 6, Config: &accepted, DesiredConfig: &desired, Users: []protocol.User{}, Sequence: 42}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	if snapshot.AgentID != data.AgentID || snapshot.Revision != 7 || snapshot.ConfigRevision != 6 || snapshot.Sequence != 42 {
		t.Fatal("identity/revisions/accounting sequence changed", snapshot)
	}
	if snapshot.Config.DNS.Mode != "xray" || !bytes.Contains(snapshot.Config.Xray, []byte(`127.0.0.1`)) || snapshot.DesiredConfig.DNS.Mode != "xray" || !bytes.Contains(snapshot.DesiredConfig.Xray, []byte(`192.0.2.53`)) {
		t.Fatal("bootstrap lost effective DNS", snapshot.Config, snapshot.DesiredConfig)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("DNS migration rewrote durable state", err)
	}
}
