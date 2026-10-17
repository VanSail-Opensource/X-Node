package firewall

import (
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"net/netip"
)

func validateUpdate(update protocol.FirewallUpdate) error {
	if !update.SourcesOnly && (len(update.Sources) > 0 || len(update.RemoveSources) > 0 || update.SourcesComplete) {
		return errors.New("source inventories require a source-only snapshot")
	}
	if update.SourcesOnly && (len(update.Bans) > 0 || len(update.Exemptions) > 0 || len(update.Remove) > 0 || len(update.RemoveExemptions) > 0) {
		return errors.New("source snapshots cannot change dynamic restrictions")
	}
	if update.Version == 0 || !protocol.ValidName(update.SnapshotID) {
		return errors.New("firewall updates require a master version and snapshot identity")
	}
	if len(update.Bans) > 5000 || len(update.Exemptions) > 5000 || len(update.Sources) > 128 || len(update.Remove) > 5000 || len(update.RemoveExemptions) > 5000 {
		return errors.New("firewall chunk exceeds limit")
	}
	for _, ban := range update.Bans {
		if err := ban.Validate(); err != nil {
			return err
		}
	}
	for _, exemption := range update.Exemptions {
		if err := exemption.Validate(); err != nil {
			return err
		}
	}
	for _, source := range update.Sources {
		if source.Reference && len(source.Prefixes) > 0 {
			return errors.New("source references cannot carry prefixes")
		}
		if !protocol.ValidName(source.ID) || !protocol.ValidName(source.Generation) || source.Until.IsZero() || source.RefreshSeconds < 1 || source.RefreshSeconds > 31536000 || len(source.Prefixes) > 10000 {
			return errors.New("invalid firewall source chunk")
		}
		for _, raw := range source.Prefixes {
			if _, err := protocol.FirewallPrefix(raw); err != nil {
				return err
			}
		}
	}
	for _, raw := range update.Remove {
		if _, err := protocol.FirewallPrefix(raw); err != nil {
			return err
		}
	}
	for _, raw := range update.RemoveExemptions {
		if _, err := netip.ParseAddr(raw); err != nil {
			return err
		}
	}
	return nil
}
