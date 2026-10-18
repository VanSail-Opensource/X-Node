package state

import (
	"errors"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Stage retains a validated activation target across listener failures/restarts.
// The last successfully applied Config and ConfigRevision remain unchanged.
func (s *Store) Stage(c protocol.Config, revision uint64) error {
	return s.change(func(d *Data) error {
		if revision != d.Revision {
			return errors.New("authorization revision changed")
		}
		c = protocol.Clone(c)
		c.Users = protocol.Clone(d.Users)
		d.DesiredConfig = &c
		return nil
	})
}
