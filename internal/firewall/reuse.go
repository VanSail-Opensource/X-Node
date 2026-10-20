package firewall

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Reuse retains the original transaction/rollback identity for an identical
// pending policy, or reuses confirmed native ownership. Expired/legacy state
// goes through the normal recovery/migration path instead.
func (m *Manager) Reuse(ctx context.Context, policy protocol.FirewallPolicy, redirect bool) (Pending, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	release, err := m.locked(ctx)
	if err != nil {
		return Pending{}, false, err
	}
	defer release()
	current, err := readRecord(m.path())
	if err != nil && !os.IsNotExist(err) {
		return Pending{}, false, err
	}
	if err == nil && current.Status == "pending" {
		return current.Pending, current.Deadline.After(time.Now()) && samePolicy(current, policy, redirect), nil
	}
	confirmed, err := readRecord(filepath.Join(m.Dir, "policy.json"))
	if os.IsNotExist(err) {
		return Pending{}, false, nil
	}
	if err != nil {
		return Pending{}, false, err
	}
	return confirmed.Pending, confirmed.Engine == 1 && confirmed.Ownership && confirmed.Status == "confirmed" && samePolicy(confirmed, policy, redirect), nil
}

func samePolicy(record record, policy protocol.FirewallPolicy, redirect bool) bool {
	a, _ := json.Marshal(record.Policy)
	b, _ := json.Marshal(policy)
	return string(a) == string(b) && record.Redirect == redirect
}
