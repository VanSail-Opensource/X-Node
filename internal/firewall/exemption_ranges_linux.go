//go:build linux

package firewall

import (
	"bytes"
	"container/heap"
	"net/netip"
	"sort"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables"
	"go4.org/netipx"
)

type exemptionBoundary struct {
	at             netip.Addr
	index          int
	open, afterMax bool
}
type exemptionDeadline struct {
	until time.Time
	index int
}
type exemptionHeap []exemptionDeadline

func (h exemptionHeap) Len() int           { return len(h) }
func (h exemptionHeap) Less(i, j int) bool { return h[i].until.After(h[j].until) }
func (h exemptionHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *exemptionHeap) Push(v any)        { *h = append(*h, v.(exemptionDeadline)) }
func (h *exemptionHeap) Pop() any          { old := *h; v := old[len(old)-1]; *h = old[:len(old)-1]; return v }

// Overlapping grants become disjoint timed intervals without extending a shorter
// outer grant to the expiry of a longer inner grant.
func exemptionRangeElements(items []protocol.FirewallExemption, now time.Time, v6 bool) ([]nftables.SetElement, error) {
	boundaries := []exemptionBoundary{}
	for index, item := range items {
		p, err := protocol.ExemptionPrefix(item.IP)
		if err != nil {
			return nil, err
		}
		if p.Addr().Is6() != v6 || p.Bits() == p.Addr().BitLen() || !item.Until.After(now) {
			continue
		}
		r := netipx.RangeOfPrefix(p)
		end := r.To().Next()
		boundaries = append(boundaries, exemptionBoundary{at: r.From(), index: index, open: true}, exemptionBoundary{at: end, index: index, afterMax: !end.IsValid()})
	}
	sort.Slice(boundaries, func(i, j int) bool {
		a, b := boundaries[i], boundaries[j]
		if a.afterMax != b.afterMax {
			return !a.afterMax
		}
		c := a.at.Compare(b.at)
		return c < 0 || c == 0 && !a.open && b.open
	})
	active := make([]bool, len(items))
	deadlines := exemptionHeap{}
	var previous netip.Addr
	result := []nftables.SetElement{}
	for i := 0; i < len(boundaries); {
		current := boundaries[i]
		for deadlines.Len() > 0 && !active[deadlines[0].index] {
			heap.Pop(&deadlines)
		}
		if previous.IsValid() && deadlines.Len() > 0 && (current.afterMax || previous.Compare(current.at) < 0) {
			end := current.at.AsSlice()
			if current.afterMax {
				size := 4
				if v6 {
					size = 16
				}
				end = make([]byte, size)
			}
			result = append(result, nftables.SetElement{Key: previous.AsSlice(), Timeout: deadlines[0].until.Sub(now)}, nftables.SetElement{Key: end, IntervalEnd: true})
		}
		j := i
		for j < len(boundaries) && boundaries[j].at == current.at && boundaries[j].afterMax == current.afterMax {
			event := boundaries[j]
			active[event.index] = event.open
			if event.open {
				heap.Push(&deadlines, exemptionDeadline{until: items[event.index].Until, index: event.index})
			}
			j++
		}
		previous = current.at
		i = j
	}
	sort.SliceStable(result, func(i, j int) bool {
		c := bytes.Compare(result[i].Key, result[j].Key)
		return c < 0 || c == 0 && result[i].IntervalEnd && !result[j].IntervalEnd
	})
	return result, nil
}
