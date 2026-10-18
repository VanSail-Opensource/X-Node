//go:build linux

package firewall

import (
	"github.com/google/nftables"
	"time"
)

func timeoutDelta(current, desired []nftables.SetElement) (add, remove []nftables.SetElement) {
	existing := map[string]nftables.SetElement{}
	for _, item := range current {
		existing[timeoutElementKey(item)] = item
	}
	for _, item := range desired {
		old, ok := existing[timeoutElementKey(item)]
		if !ok {
			add = append(add, item)
		} else if delta := old.Expires - item.Timeout; delta > 100*time.Millisecond || delta < -100*time.Millisecond {
			remove = append(remove, old)
			add = append(add, item)
		}
		delete(existing, timeoutElementKey(item))
	}
	for _, item := range existing {
		remove = append(remove, item)
	}
	return
}
func changeElements(c *nftables.Conn, set *nftables.Set, elements []nftables.SetElement, add bool) error {
	for len(elements) > 0 {
		count := min(512, len(elements))
		chunk := elements[:count]
		var err error
		if add {
			err = c.SetAddElements(set, chunk)
		} else {
			err = c.SetDeleteElements(set, chunk)
		}
		if err != nil {
			return err
		}
		elements = elements[count:]
	}
	return nil
}

func timeoutElementKey(item nftables.SetElement) string {
	key := string(item.Key)
	if item.IntervalEnd {
		return key + "e"
	}
	return key + "s"
}
