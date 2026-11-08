package hourly

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestDemandFramesProgressFairlyAndWholeSnapshotIncludesEveryOwner(t *testing.T) {
	clock := &admissionClock{now: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	var nonce atomic.Uint64
	c := NewController(Options{Now: clock.Now, AfterFunc: clock.After, Nonce: func() string { return fmt.Sprintf("%032x", nonce.Add(1)) }})
	var authorizations []Authorization
	for i := 0; i < 512; i++ {
		key := BindingKey{Owner: OwnerKey{ID: fmt.Sprintf("account-%04d", i)}, EnrollmentID: "enrollment", PeriodID: "period", PrincipalID: i + 1}
		authorizations = append(authorizations, Authorization{key, clock.Now().Add(time.Hour)})
	}
	if !c.ApplyAuthorization(1, 1, authorizations) {
		t.Fatal("bounded fleet rejected")
	}
	c.SetSession("33333333333333333333333333333333")
	for _, authorization := range authorizations {
		flow, err := c.OpenFlow(authorization.Key, func() {})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(flow.Close)
		_, _, err = flow.TryAcquire(Upload, 1, 1)
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	for range 4 {
		for _, demand := range c.PendingDemand(128) {
			seen[demand.Owner.ID] = true
		}
	}
	if len(seen) != 512 {
		t.Fatal("later blocked owners starved behind frame limit", len(seen))
	}
	all := c.PendingDemands()
	if len(all) != 512 {
		t.Fatal("whole demand snapshot omitted owners", len(all))
	}
}
