package update

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestFirewallRestoreCandidatesPreventRangeBlindDowngrade(t *testing.T) {
	for _, name := range []string{"policy.json", "pending.json", "previous-policy.json", "candidate.json"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "firewall"), 0700); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(map[string]any{"engine": 1, "policy": protocol.FirewallPolicy{SSHPortRanges: []protocol.PortRange{{From: 22, To: 23}}}})
			if err := os.WriteFile(filepath.Join(dir, "firewall", name), raw, 0600); err != nil {
				t.Fatal(err)
			}
			m := &Manager{Dir: filepath.Join(dir, "updates")}
			caps, err := m.requiredCapabilities()
			if err != nil || !slices.Contains(caps, protocol.FirewallPortRangesCapability) {
				t.Fatal("restore lost capability", caps, err)
			}
		})
	}
}
