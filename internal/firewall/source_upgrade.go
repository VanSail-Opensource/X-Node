package firewall

import (
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/update"
)

// The first upgraded process must not make its rollback binary unable to read
// the previous source snapshot before the upgrade has been confirmed.
func (g *Guard) sourceUpgradePending() bool {
	pending, err := update.PendingTransaction(filepath.Join(filepath.Dir(g.dir), "updates"))
	return err != nil || pending
}
