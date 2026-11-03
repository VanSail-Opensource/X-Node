package sessions

import (
	"cmp"
	"container/list"
	"math"
	"slices"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

const activityHistoryAge = 2 * time.Hour

type activityIP struct {
	user int
	ip   string
}
type activityRecord struct {
	key   activityIP
	at    time.Time
	count uint64
}
type activityHistory struct {
	sampled time.Time
	pending map[activityIP]time.Time
	entries map[activityIP]*list.Element
	lru     list.List
	dropped uint64
}

// Closing a brief flow keeps evidence until the next configured sample. This
// never touches disk, and no packet adds a map entry or takes the registry lock.
func (h *activityHistory) close(lease *Lease) {
	bytes := lease.bytes.Load()
	if lease.transit || bytes <= lease.sampledBytes {
		return
	}
	lease.sampledBytes = bytes
	key := activityIP{lease.Info.UserID, lease.Info.SourceIP}
	if h.pending == nil {
		h.pending = map[activityIP]time.Time{}
	}
	if _, exists := h.pending[key]; !exists && len(h.pending) >= protocol.MaxActivityObservations {
		h.drop()
		return
	}
	h.pending[key] = time.Now().UTC()
}

func (h *activityHistory) observe(key activityIP, at time.Time) {
	if h.entries == nil {
		h.entries = map[activityIP]*list.Element{}
	}
	if entry := h.entries[key]; entry != nil {
		value := entry.Value.(activityRecord)
		if at.After(value.at) {
			value.at = at
			if value.count < math.MaxUint64 {
				value.count++
			}
			entry.Value = value
			h.lru.MoveToFront(entry)
		}
		return
	}
	if len(h.entries) >= protocol.MaxActivityObservations {
		h.remove(h.lru.Back())
		h.drop()
	}
	h.entries[key] = h.lru.PushFront(activityRecord{key, at, 1})
}

func (h *activityHistory) drop() {
	if h.dropped < math.MaxUint64 {
		h.dropped++
	}
}
func (h *activityHistory) remove(entry *list.Element) {
	delete(h.entries, entry.Value.(activityRecord).key)
	h.lru.Remove(entry)
}

func (h *activityHistory) sample(now time.Time, active map[int]map[string]int) {
	for entry := h.lru.Back(); entry != nil; {
		previous := entry.Prev()
		at := entry.Value.(activityRecord).at
		if !at.After(now.Add(-activityHistoryAge)) || at.After(now) {
			h.remove(entry)
		}
		entry = previous
	}
	for key, at := range h.pending {
		if at.After(now.Add(-activityHistoryAge)) && !at.After(now) {
			h.observe(key, at)
		}
	}
	clear(h.pending)
	for user, ips := range active {
		for ip := range ips {
			h.observe(activityIP{user, ip}, now)
		}
	}
	h.sampled = now
}

func (h *activityHistory) snapshot(summary *Summary) {
	if !h.sampled.IsZero() {
		at := h.sampled
		summary.SampledAt = &at
	} else {
		return
	}
	summary.ObservationDrops = h.dropped
	summary.ActiveIPObservations = make([]protocol.IPActivity, 0, len(h.entries))
	for key, entry := range h.entries {
		v := entry.Value.(activityRecord)
		summary.ActiveIPObservations = append(summary.ActiveIPObservations, protocol.IPActivity{UserID: key.user, IP: key.ip, LastActive: v.at, Observations: v.count})
	}
	slices.SortFunc(summary.ActiveIPObservations, func(a, b protocol.IPActivity) int {
		return cmp.Or(cmp.Compare(a.UserID, b.UserID), cmp.Compare(a.IP, b.IP))
	})
}
