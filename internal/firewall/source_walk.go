package firewall

import (
	"context"
	"go4.org/netipx"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func walkSourceRecords(ctx context.Context, dir string, sources []protocol.FirewallSource, v6 bool, visit func(diskRange) error) error {
	paths := []string{}
	for _, source := range sources {
		if !source.Until.After(time.Now()) {
			continue
		}
		if len(source.Prefixes) > 0 {
			// Native backend fixtures can still provide small inline inventories.
			var builder netipx.IPSetBuilder
			for _, s := range sources {
				if s.Until.After(time.Now()) {
					for _, raw := range s.Prefixes {
						p, e := protocol.FirewallPrefix(raw)
						if e != nil {
							return e
						}
						if p.Addr().Is6() == v6 {
							builder.AddPrefix(p)
						}
					}
				}
			}
			index, err := builder.IPSet()
			if err != nil {
				return err
			}
			ranges := index.Ranges()
			for _, r := range ranges {
				record := diskRange{}
				record[0] = 4
				if v6 {
					record[0] = 6
				}
				a, b := r.From().As16(), r.To().As16()
				copy(record[1:17], a[:])
				copy(record[17:], b[:])
				if err = visit(record); err != nil {
					return err
				}
			}
			return nil
		}
		paths = append(paths, sourcePath(dir, source.ID, source.Generation))
	}
	return mergeRangeFiles(ctx, paths, func(record diskRange) error {
		if (record[0] == 6) == v6 {
			return visit(record)
		}
		return nil
	})
}
