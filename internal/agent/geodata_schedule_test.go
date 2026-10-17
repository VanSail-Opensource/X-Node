package agent

import (
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/geodata"
	"testing"
	"time"
)

func TestCompletionScheduleRetriesAndSupersession(t *testing.T) {
	hours := 24
	p := geodata.Policy{IntervalHours: &hours}
	a := &Agent{}
	a.scheduleGeodata(p)
	first := a.geoNext.Load()
	a.scheduleGeodata(p)
	if a.geoNext.Load() != first {
		t.Fatal("unrelated apply postponed refresh")
	}
	for _, delay := range []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 24 * time.Hour} {
		before := time.Now()
		a.finishGeodata(p, errors.New("provider failed"))
		delta := time.Unix(0, a.geoNext.Load()).Sub(before)
		if delta < delay || delta > delay+time.Second {
			t.Fatalf("retry delay=%v want %v", delta, delay)
		}
	}
	a.finishGeodata(p, nil)
	if a.geoFailures != 0 {
		t.Fatal("success did not reset failures")
	}
	zero := 0
	disabled := geodata.Policy{IntervalHours: &zero}
	a.scheduleGeodata(disabled)
	a.finishGeodata(p, nil)
	if a.geoNext.Load() != 0 {
		t.Fatal("superseded completion re-enabled schedule")
	}
}
