package hourly

import (
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func BenchmarkSmallHourlyHandoff(b *testing.B) {
	now := time.Date(2026, 11, 26, 11, 0, 0, 0, time.UTC)
	controller := NewController(Options{
		Now:   func() time.Time { now = now.Add(time.Microsecond); return now },
		Nonce: func() string { return "77777777777777777777777777777777" },
	})
	binding := BindingKey{Owner: OwnerKey{ID: "account", Generation: 7}, EnrollmentID: "enrollment", PeriodID: "period", PrincipalID: 1}
	session := "33333333333333333333333333333333"
	controller.SetSession(session)
	if !controller.ApplyAuthorization(1, 1, []Authorization{{Key: binding, PaidThrough: now.Add(time.Hour)}}) {
		b.Fatal("authorization")
	}
	flow, err := controller.OpenFlow(binding, func() {})
	if err != nil {
		b.Fatal(err)
	}
	if _, _, err = flow.TryAcquire(Download, 128, 1); err != nil {
		b.Fatal(err)
	}
	demands := controller.PendingDemand(1)
	if len(demands) != 1 {
		b.Fatal("expected one pending demand")
	}
	if _, err = controller.ApplyGrant(protocol.HourlyGrant{SessionID: session, Owner: demands[0].Owner, Nonce: demands[0].Nonce, Sequence: 1, DayUTC: now.Format(time.DateOnly), LifetimeMillis: protocol.MaxHourlyLifetimeMillis, RateBytesPerSecond: 1000000000, BurstBytes: 16384}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(128)
	for b.Loop() {
		permit, _, err := flow.TryAcquire(Download, 128, 1)
		if err != nil || permit == nil {
			b.Fatalf("permit: %v", err)
		}
		if err := permit.Begin(); err != nil {
			b.Fatal(err)
		}
		permit.Complete(Accepted)
	}
}
