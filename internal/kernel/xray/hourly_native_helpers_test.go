package xray

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
)

const nativeHourlySession = "11111111111111111111111111111111"

func nativeHourlyRegistry(t *testing.T, cfg *protocol.Config) (*sessions.Registry, *hourly.Controller) {
	t.Helper()
	paid := time.Now().Add(time.Minute)
	cfg.Users[0].Hourly = &protocol.HourlyUser{Owner: protocol.HourlyOwner{ID: "native-owner", Generation: 1}, EnrollmentID: "native-enrollment"}
	cfg.Users[0].AccountingPeriod, cfg.Users[0].ValidUntil = "native-hourly-period", &paid
	controller := hourly.NewController(hourly.Options{})
	controller.SetSession(nativeHourlySession)
	registry := sessions.New()
	registry.SetHourlyController(controller)
	registry.SetUsers(cfg.Users)
	t.Cleanup(registry.CloseAll)
	return registry, controller
}

// The fake master answers only authentic demands. No test mints an unsolicited
// grant or restores burst tokens on reconnect.
func serveNativeHourlyGrants(t *testing.T, controller *hourly.Controller) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	workers.Add(1)
	errors := make(chan error, 1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		var sequence uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-controller.DemandWake():
			}
			for _, demand := range controller.PendingDemand(128) {
				sequence++
				_, err := controller.ApplyGrant(protocol.HourlyGrant{SessionID: nativeHourlySession, Owner: demand.Owner, Nonce: demand.Nonce, Sequence: sequence, DayUTC: time.Now().UTC().Format(time.DateOnly), LifetimeMillis: 10000, RateBytesPerSecond: 1_000_000, BurstBytes: 16384})
				if err != nil {
					select {
					case errors <- err:
					default:
					}
					return
				}
			}
		}
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			workers.Wait()
			select {
			case err := <-errors:
				t.Error("native grant responder failed", err)
			default:
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func assertNativeHourlySamples(t *testing.T, controller *hourly.Controller, expected uint64) {
	t.Helper()
	var upload, download uint64
	for _, sample := range controller.Samples() {
		if sample.Owner.ID != "native-owner" || sample.Owner.Generation != 1 || sample.EnrollmentID != "native-enrollment" || sample.AccountingPeriod != "native-hourly-period" || sample.UserID != 1 || sample.CounterGeneration == 0 {
			t.Fatal("raw admitted bytes lost their immutable financial binding")
		}
		upload += sample.UploadBytes
		download += sample.DownloadBytes
	}
	if upload != expected || download != expected {
		t.Fatalf("raw hourly admissions upload=%d download=%d expected=%d", upload, download, expected)
	}
}

// core.Dial connections need not implement deadlines. A safety close bounds a
// failed native fence but must never count as evidence that enforcement worked.
func boundHourlyIO(t *testing.T, conn net.Conn) func() {
	t.Helper()
	fired := make(chan struct{})
	timer := time.AfterFunc(3*time.Second, func() {
		close(fired)
		_ = conn.Close()
	})
	return func() {
		if !timer.Stop() {
			<-fired
			t.Error("hourly native I/O required the test safety close")
		}
	}
}
