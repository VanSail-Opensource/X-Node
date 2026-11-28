package sessions

import (
	"fmt"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestSummaryOrdersDetachedActivityObservations(t *testing.T) {
	r := New()
	at := time.Now().UTC()
	earlier := at.Add(-time.Second)
	h := &r.activityHistory
	h.sampled = at
	h.observe(activityIP{11, "192.0.2.1"}, at)
	h.observe(activityIP{2, "2001:db8::2"}, earlier)
	h.observe(activityIP{2, "192.0.2.8"}, earlier)
	h.observe(activityIP{2, "2001:db8::2"}, at)
	h.observe(activityIP{2, "192.0.2.10"}, at)
	want := []protocol.IPActivity{
		{UserID: 2, IP: "192.0.2.10", LastActive: at, Observations: 1},
		{UserID: 2, IP: "192.0.2.8", LastActive: earlier, Observations: 1},
		{UserID: 2, IP: "2001:db8::2", LastActive: at, Observations: 2},
		{UserID: 11, IP: "192.0.2.1", LastActive: at, Observations: 1},
	}
	for range 10 {
		got := r.Summary().ActiveIPObservations
		if !slices.Equal(got, want) {
			t.Fatalf("history = %+v, want %+v", got, want)
		}
		got[0] = protocol.IPActivity{}
	}
}

func TestBriefClosedActivitySurvivesSamplingWithoutBecomingAnOpenFlow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, u := New(), testUser()
		r.SetUsers([]protocol.User{u})
		lease, err := acquire(r, u, "8.8.8.8", "tcp")
		if err != nil {
			t.Fatal(err)
		}
		lease.Account(true, 12)
		at := time.Now().UTC()
		lease.Close()
		if r.Summary().SampledAt != nil {
			t.Fatal("close bypassed sampling cadence")
		}
		time.Sleep(time.Second)
		r.SampleActivity()
		first := r.Summary()
		if len(first.ActiveIPObservations) != 1 || !first.ActiveIPObservations[0].LastActive.Equal(at) || first.ActiveIPObservations[0].Observations != 1 || first.Connections[u.ID] != 0 || first.TotalConnections[u.ID] != 0 {
			t.Fatal("brief payload evidence lost or counted as open", first)
		}
		copyAt := *first.SampledAt
		time.Sleep(time.Second)
		r.SampleActivity()
		second := r.Summary()
		if !second.SampledAt.After(copyAt) || second.ActiveIPObservations[0] != first.ActiveIPObservations[0] {
			t.Fatal("idle sample invented a new IP observation", second)
		}
		first.ActiveIPObservations[0].IP = "modified"
		*first.SampledAt = time.Time{}
		if r.Summary().SampledAt.IsZero() || r.Summary().ActiveIPObservations[0].IP != "8.8.8.8" {
			t.Fatal("snapshot aliases registry memory")
		}
		time.Sleep(activityHistoryAge)
		r.SampleActivity()
		if len(r.Summary().ActiveIPObservations) != 0 {
			t.Fatal("expired IP history retained")
		}
	})
}

func TestActivityHistoryBoundsAndLiveObservationRefresh(t *testing.T) {
	h := &activityHistory{}
	at := time.Now().UTC()
	for i := range protocol.MaxActivityObservations + 100 {
		h.observe(activityIP{1, fmt.Sprintf("10.%d.%d.%d", i>>16, i>>8&255, i&255)}, at)
	}
	if len(h.entries) != protocol.MaxActivityObservations || h.dropped != 100 {
		t.Fatal("unbounded observation bank", len(h.entries), h.dropped)
	}
	key := activityIP{1, "8.8.8.8"}
	h.observe(key, at)
	h.observe(key, at.Add(time.Second))
	h.observe(key, at)
	value := h.entries[key].Value.(*activityRecord)
	if value.count != 2 || !value.at.Equal(at.Add(time.Second)) {
		t.Fatal("duplicate or reordered observation advanced the counter", value)
	}
	h.sample(at.Add(-time.Second), nil)
	if len(h.entries) != 0 {
		t.Fatal("clock rollback published future observations")
	}
}
