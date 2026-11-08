package agent

import (
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

type captureHourlyStopper struct{}

func (captureHourlyStopper) Stop() bool { return true }

func captureHourlyFixture(t *testing.T) (*Agent, *hourly.Controller, *hourly.Flow, hourly.BindingKey, *time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	const session = "11111111111111111111111111111111"
	controller := hourly.NewController(hourly.Options{Now: func() time.Time { return now }, AfterFunc: func(time.Duration, func()) hourly.Stopper { return captureHourlyStopper{} }, Nonce: func() string { return "22222222222222222222222222222222" }})
	key := hourly.BindingKey{Owner: hourly.OwnerKey{ID: "account", Generation: 4}, EnrollmentID: "enrollment", PeriodID: "paid", PrincipalID: 1}
	if !controller.ApplyAuthorization(1, 1, []hourly.Authorization{{Key: key, PaidThrough: now.Add(time.Hour)}}) {
		t.Fatal("hourly authorization rejected")
	}
	controller.SetSession(session)
	flow, err := controller.OpenFlow(key, func() {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(flow.Close)
	if permit, _, err := flow.TryAcquire(hourly.Upload, 10, 1); err != nil || permit != nil {
		t.Fatal("unexpected admission without grant", err)
	}
	demands := controller.PendingDemand(1)
	if len(demands) != 1 {
		t.Fatal("missing hourly demand", demands)
	}
	grant := protocol.HourlyGrant{SessionID: session, Owner: demands[0].Owner, Nonce: demands[0].Nonce, Sequence: 1, DayUTC: now.Format(time.DateOnly), LifetimeMillis: 10000, RateBytesPerSecond: 1000, BurstBytes: 1024}
	if _, err = controller.ApplyGrant(grant); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	process := &Agent{Store: store, Registry: sessions.New(), hourly: &hourlyRuntime{controller: controller}, previous: state.Traffic{}, previousAccounting: map[string][2]uint64{}}
	return process, controller, flow, key, &now
}

func admitHourlyCapture(t *testing.T, flow *hourly.Flow, direction hourly.Direction, bytes int) {
	t.Helper()
	permit, _, err := flow.TryAcquire(direction, bytes, 1)
	if err != nil || permit == nil || permit.Bytes() != bytes {
		t.Fatal("hourly fixture could not reserve payload", err)
	}
	if err = permit.Begin(); err != nil {
		t.Fatal(err)
	}
	permit.Complete(hourly.NotHandedOff)
}
