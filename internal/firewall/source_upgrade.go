package firewall

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// The first upgraded process must not make its rollback binary unable to read
// the previous source snapshot before the upgrade has been confirmed.
func (g *Guard) sourceUpgradePending() bool {
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(g.dir), "updates", "transaction.json"))
	if err != nil {
		return !os.IsNotExist(err)
	}
	var transaction struct {
		Status string `json:"status"`
	}
	return json.Unmarshal(raw, &transaction) != nil || transaction.Status == "pending"
}
