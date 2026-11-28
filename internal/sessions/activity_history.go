package sessions

import (
	"container/list"
	"math"
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
		value := entry.Value.(*activityRecord)
		if at.After(value.at) {
			value.at = at
			if value.count < math.MaxUint64 {
				value.count++
			}
			h.lru.MoveToFront(entry)
		}
		return
	}
	if len(h.entries) >= protocol.MaxActivityObservations {
		h.remove(h.lru.Back())
		h.drop()
	}
	h.entries[key] = h.lru.PushFront(&activityRecord{key, at, 1})
}

func (h *activityHistory) drop() {
	if h.dropped < math.MaxUint64 {
		h.dropped++
	}
}
func (h *activityHistory) remove(entry *list.Element) {
	delete(h.entries, entry.Value.(*activityRecord).key)
	h.lru.Remove(entry)
}

func (h *activityHistory) sample(now time.Time, active map[int]map[string]int) {
	cutoff := now.Add(-activityHistoryAge)
	for entry := h.lru.Back(); entry != nil; {
		previous := entry.Prev()
		at := entry.Value.(*activityRecord).at
		if !at.After(cutoff) || at.After(now) {
			h.remove(entry)
		}
		entry = previous
	}
	for key, at := range h.pending {
		if at.After(cutoff) && !at.After(now) {
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
		v := entry.Value.(*activityRecord)
		summary.ActiveIPObservations = append(summary.ActiveIPObservations, protocol.IPActivity{UserID: key.user, IP: key.ip, LastActive: v.at, Observations: v.count})
	}
}

// Compare by index so each comparison does not copy two full observations.
type activityObservations []protocol.IPActivity

func (s activityObservations) Len() int      { return len(s) }
func (s activityObservations) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s activityObservations) Less(i, j int) bool {
	left, right := &s[i], &s[j]
	if left.UserID != right.UserID {
		return left.UserID < right.UserID
	}
	return left.IP < right.IP
}
