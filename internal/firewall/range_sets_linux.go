//go:build linux

package firewall

import (
	"context"
	"github.com/google/nftables"
)

func populateRangeSet(ctx context.Context, set *nftables.Set, last diskRange, count int, walk func(func(diskRange) error) error) error {
	if err := admitRangeSet(ctx, count); err != nil {
		return err
	}
	set.Size = uint32(count*2 + 2)
	c, close, err := connection(ctx)
	if err != nil {
		return err
	}
	c.AddTable(set.Table)
	if err = c.AddSet(set, nil); err == nil {
		err = c.Flush()
	}
	close()
	if err != nil {
		return err
	}
	set.ID = 0
	var elements []nftables.SetElement
	_, lastIP := last.addresses()
	wrap := last[0] != 0 && !lastIP.Next().IsValid()
	if wrap {
		first, _ := last.addresses()
		elements = append(elements, nftables.SetElement{Key: make([]byte, set.KeyType.Bytes), IntervalEnd: true}, nftables.SetElement{Key: first.AsSlice()})
	}
	err = walk(func(record diskRange) error {
		if wrap && record == last {
			return nil
		}
		first, last := record.addresses()
		elements = append(elements, nftables.SetElement{Key: first.AsSlice()}, nftables.SetElement{Key: last.Next().AsSlice(), IntervalEnd: true})
		if len(elements) >= 512 {
			if err := populateSource(ctx, set, elements); err != nil {
				return err
			}
			elements = nil
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(elements) > 0 {
		return populateSource(ctx, set, elements)
	}
	return nil
}
