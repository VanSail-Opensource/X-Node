package sessions

import (
	"context"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type delayedHourlyTimer struct{ fire func() }

func (*delayedHourlyTimer) Stop() bool { return true }

func TestHourlyMaintenanceExpiryAndLateTimerRespectRenewal(t *testing.T) {
	for _, renewal := range []bool{false, true} {
		t.Run(map[bool]string{false: "maintenance-first", true: "renewal-first"}[renewal], func(t *testing.T) {
			base := time.Now().UTC()
			now := base
			var timers []*delayedHourlyTimer
			controller := hourly.NewController(hourly.Options{Now: func() time.Time { return now }, AfterFunc: func(_ time.Duration, fn func()) hourly.Stopper {
				timer := &delayedHourlyTimer{fire: fn}
				timers = append(timers, timer)
				return timer
			}})
			r, user := New(), sessionHourlyUser()
			paid := base.Add(time.Second)
			user.ValidUntil = &paid
			r.SetHourlyController(controller)
			r.SetUsers([]protocol.User{user})
			fenced := 0
			lease, err := r.AcquireTrackedWithHourlyFence(context.Background(), user.ID, protocol.UserEmail(user, "in"), "in", "192.0.2.1", "example.com:443", "tcp", 443, nil, func() { _ = r.Summary(); fenced++ })
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Finish()
			defer lease.Close()
			oldTimer := timers[len(timers)-1]
			now = paid
			if renewal {
				until := base.Add(time.Hour)
				user.ValidUntil = &until
				r.SetUsers([]protocol.User{user})
			}
			r.ExpireUsers(now)
			// A callback already queued before Stop may resume after maintenance
			// or after a newer authorization has replaced its paid boundary.
			oldTimer.fire()
			r.ExpireUsers(now)
			if renewal {
				flow, _ := lease.HourlyFlow()
				if fenced != 0 || lease.closed || flow == nil {
					t.Fatal("old expiry observation revoked a paid renewal")
				}
				if _, _, err = flow.TryAcquire(hourly.Upload, 1, 1); err != nil {
					t.Fatal("renewed binding remained fenced", err)
				}
			} else if fenced != 1 || !lease.closed || r.Summary().TotalConnections[user.ID] != 0 {
				t.Fatal("maintenance skipped or duplicated native transport fencing", fenced)
			}
		})
	}
}
