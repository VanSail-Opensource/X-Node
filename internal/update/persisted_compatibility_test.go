package update

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/config"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func TestPersistedPolicyCapabilitiesSurviveUpgradeAndRollback(t *testing.T) {
	for _, test := range []struct {
		name, marker, capability string
		policy                   protocol.Config
	}{
		{name: "disk sources", marker: "disk-sources-v1", capability: "disk_firewall_sources_v1"},
		{name: "CIDR exemptions", marker: "cidr-exemptions-v1", capability: "firewall_cidr_exemptions_v1"},
		{name: "streamed country ranges", capability: "source_geoip_stream_v1", policy: protocol.Config{Firewall: protocol.FirewallPolicy{SourceGeoIP: &protocol.SourceGeoIPPolicy{Reference: true}}}},
		{name: "node file certificate", capability: "node_file_certificates_v1", policy: protocol.Config{Certificates: map[string]protocol.Certificate{"tls": {Config: config.CertConfig{CertMode: "file", CertFile: "/private/cert.pem", KeyFile: "/private/key.pem"}}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if test.marker != "" {
				fw := filepath.Join(dir, "firewall")
				if err := os.MkdirAll(fw, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(fw, test.marker), []byte("1"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, staged := range []bool{false, true} {
				data := state.Data{AgentID: "fixture"}
				if staged {
					data.DesiredConfig = &test.policy
				} else {
					data.Config = &test.policy
				}
				raw, err := json.Marshal(data)
				if err != nil {
					t.Fatal(err)
				}
				if err = state.AtomicWrite(filepath.Join(dir, "state.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
				m := &Manager{Dir: filepath.Join(dir, "updates")}
				required, err := m.requiredCapabilities()
				if err != nil {
					t.Fatal(err)
				}
				metadata, err := json.Marshal(map[string]any{"capabilities": required})
				if err != nil || m.checkCapabilities(metadata) != nil {
					t.Fatal("compatible replacement rejected", err)
				}
				filtered := []string{}
				for _, capability := range required {
					if capability != test.capability {
						filtered = append(filtered, capability)
					}
				}
				metadata, err = json.Marshal(map[string]any{"capabilities": filtered})
				if err != nil {
					t.Fatal(err)
				}
				if err = m.checkCapabilities(metadata); err == nil {
					t.Fatalf("replacement lost %s (staged=%v)", test.capability, staged)
				}
			}
		})
	}
}
