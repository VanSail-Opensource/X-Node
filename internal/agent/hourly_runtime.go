package agent

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type hourlyGrantReceipt struct {
	ack   protocol.HourlyGrantAck
	drain *hourly.Drain
}

// Durable credit work never runs on the state actor or socket writer. Only the
// synchronous, memory-only session fence runs in the transport callback.
type hourlyRuntime struct {
	controller  *hourly.Controller
	store       *hourly.CreditStore
	creditMu    sync.Mutex
	installed   map[string]protocol.HourlyCreditInstall
	ackMu       sync.Mutex
	acks        map[protocol.HourlyOwner]hourlyGrantReceipt
	operationMu sync.Mutex
	operations  sync.WaitGroup
	stopping    atomic.Bool
}

func (a *Agent) initializeHourly() {
	store, err := hourly.OpenCreditStore(filepath.Join(a.Dir, "hourly-credits.json"))
	h := &hourlyRuntime{controller: hourly.NewController(hourly.Options{}), store: store, installed: map[string]protocol.HourlyCreditInstall{}, acks: map[protocol.HourlyOwner]hourlyGrantReceipt{}}
	a.hourly = h
	a.Registry.SetHourlyController(h.controller)
	a.Client.OnHourlySession = func(session string) { h.controller.SetSession(session) }
	ready := a.hourlyAvailable()
	a.Client.SetHourlyEnabled(ready)
	if err != nil || !ready {
		nlog.Core().Warn("hourly credit journal unavailable; hourly access disabled")
	}
}

func (a *Agent) runtimeCapabilities() []string {
	if a.hourlyAvailable() {
		return BinaryCapabilities()
	}
	return append([]string(nil), Capabilities...)
}

// BinaryCapabilities reports format support for upgrade/rollback checks.
// Operational hello remains gated on the actual hourly store/controller health.
func BinaryCapabilities() []string {
	return append(append([]string(nil), Capabilities...), protocol.HourlyCapability)
}

func (a *Agent) runHourly(ctx context.Context) func() {
	if a.hourly == nil {
		return func() {}
	}
	child, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	workers.Go(func() { a.publishHourly(child) })
	workers.Go(func() { a.retireHourlyCredits(child) })
	var stop sync.Once
	return func() {
		stop.Do(func() {
			cancel()
			// The process signal has already cancelled ctx. Financial cleanup
			// gets its own bounded opportunity to persist before runtime teardown.
			cleanup, finish := context.WithTimeout(context.Background(), 5*time.Second)
			defer finish()
			if err := a.shutdownHourly(cleanup, &workers); err != nil {
				nlog.Core().Warn("hourly shutdown did not finish; unsealed credit remains recoverable", "error", err)
			}
		})
	}
}

func (a *Agent) checkHourlyHealth() bool {
	if a.hourly != nil && a.hourly.stopping.Load() {
		// Session clearing can invoke native interrupt hooks. It must not hold
		// an accepted durable command open while shutdown is joining it.
		return false
	}
	healthy := a.hourlyAvailable()
	if !healthy {
		a.Client.SetHourlyEnabled(false)
	}
	return healthy
}

func (a *Agent) hourlyAvailable() bool {
	return a.hourly != nil && !a.hourly.stopping.Load() && a.hourly.store.Healthy() && a.hourly.store.MatchesAgent(a.Store.Metadata().AgentID)
}
