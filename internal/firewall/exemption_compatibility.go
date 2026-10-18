package firewall

import (
	"errors"
	"os"
	"strings"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func (g *Guard) markExemptionFormat(items []protocol.FirewallExemption) error {
	for _, item := range items {
		if strings.Contains(item.IP, "/") {
			if _, err := os.Stat(g.file("cidr-exemptions-v1")); os.IsNotExist(err) && g.sourceUpgradePending() {
				return errors.New("CIDR exemption migration awaits update confirmation")
			} else if err != nil && !os.IsNotExist(err) {
				return err
			}
			return state.AtomicWrite(g.file("cidr-exemptions-v1"), []byte("v1\n"), 0600)
		}
	}
	return nil
}
