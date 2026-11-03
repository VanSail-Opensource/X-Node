package firewall

import (
	"container/heap"
	"errors"
	"net/netip"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type automaticEntry struct {
	ip           netip.Addr
	epoch        string
	generation   uint64
	until, prior time.Time
	index        int
}

func (e automaticEntry) deadline() time.Time {
	if e.prior.After(e.until) {
		return e.prior
	}
	return e.until
}

type automaticBank struct {
	entries map[netip.Addr]*automaticEntry
	expiry  automaticExpiry
	loaded  bool
	dirty   bool
}

func (b *automaticBank) prune(now time.Time) {
	for len(b.expiry) > 0 && !b.expiry[0].deadline().After(now) {
		item := heap.Pop(&b.expiry).(*automaticEntry)
		delete(b.entries, item.ip)
	}
}

func (b *automaticBank) stage(update protocol.AutomaticLeaseUpdate, now time.Time) (map[netip.Addr]automaticEntry, error) {
	if err := update.Validate(now); err != nil {
		return nil, err
	}
	b.prune(now)
	next := map[netip.Addr]automaticEntry{}
	added := 0
	for _, grant := range update.Leases {
		ip, _ := netip.ParseAddr(grant.IP)
		if old := b.entries[ip]; old != nil && old.epoch == update.Epoch && grant.Generation == old.generation && !grant.Until.Equal(old.until) {
			return nil, errors.New("conflicting automatic lease generation")
		}
		if !grant.Until.After(now) {
			continue
		}
		value := automaticEntry{ip: ip, index: -1}
		if old := b.entries[ip]; old != nil {
			value = *old
			if old.epoch == update.Epoch {
				if grant.Generation <= old.generation {
					continue
				}
			} else if old.deadline().After(value.prior) {
				value.prior = old.deadline()
			}
		} else {
			added++
		}
		value.epoch, value.generation, value.until = update.Epoch, grant.Generation, grant.Until
		next[ip] = value
	}
	if len(b.entries)+added > protocol.MaxAutomaticLeases {
		return nil, errors.New("automatic lease capacity reached")
	}
	return next, nil
}

func (b *automaticBank) commit(next map[netip.Addr]automaticEntry) {
	if b.entries == nil {
		b.entries = map[netip.Addr]*automaticEntry{}
	}
	for ip, value := range next {
		if old := b.entries[ip]; old != nil {
			value.index = old.index
			*old = value
			heap.Fix(&b.expiry, old.index)
		} else {
			copy := value
			b.entries[ip] = &copy
			heap.Push(&b.expiry, &copy)
		}
	}
}
