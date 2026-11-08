// Package transport owns the agent's single WebSocket and serialized writer.
package transport

import (
	"context"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/gorilla/websocket"
)

type Client struct {
	URL              string
	Token            string
	Dialer           *websocket.Dialer
	Hello            func() protocol.Message
	Incoming         chan protocol.Message
	Status           chan bool
	lanes            [5]*messageLane
	wake             chan struct{}
	reset            chan struct{}
	connected        atomic.Bool
	resync           atomic.Bool
	dropped          atomic.Uint64
	computePool      atomic.Bool
	compactTelemetry atomic.Bool
	openConnections  atomic.Bool
	ddnsChanges      atomic.Bool
	reportFraming    atomic.Bool
	trafficStreams   atomic.Bool
	activityReports  atomic.Bool
	hourlyEnabled    atomic.Bool
	hourlyMu         sync.Mutex
	hourlyNegotiated atomic.Bool
	hourlyAccounting atomic.Bool
	hourlySession    atomic.Value
	OnHourlySession  func(string)            // Set before Run; synchronous admission fence.
	reportEncoder    *protocol.ReportEncoder // serialized socket writer only
}

func New(url, token string) *Client {
	return &Client{URL: url, Token: token, Incoming: make(chan protocol.Message, 128), Status: make(chan bool, 8),
		lanes: [5]*messageLane{newMessageLane(64, 32<<20), newMessageLane(16, 32<<20), newMessageLane(1, protocol.MaxFrameBytes+128), newMessageLane(64, 4<<20), newMessageLane(24, 2<<20)},
		wake:  make(chan struct{}, 1), reset: make(chan struct{}, 1)}
}
func (c *Client) Connected() bool        { return c.connected.Load() }
func (c *Client) Dropped() uint64        { return c.dropped.Load() }
func (c *Client) CompactTelemetry() bool { return c.compactTelemetry.Load() }
func (c *Client) OpenConnections() bool  { return c.openConnections.Load() }
func (c *Client) ComputePool() bool      { return c.computePool.Load() }
func (c *Client) DDNSChanges() bool      { return c.ddnsChanges.Load() }
func (c *Client) ReportFraming() bool    { return c.reportFraming.Load() }
func (c *Client) TrafficStreams() bool   { return c.trafficStreams.Load() }
func (c *Client) ActivityReports() bool  { return c.activityReports.Load() }
func (c *Client) Send(m protocol.Message, critical bool) bool {
	lane := 3
	if critical {
		lane = 0
	}
	switch m.Type {
	case "compute.claim", "compute.heartbeat", "compute.result", "compute.cancel":
		lane = 4
		critical = false
	case "traffic.report":
		lane = 1
		critical = true
	case "telemetry.report", "telemetry.compact":
		lane = 2
		critical = false
	}
	accepted, replaced := c.lanes[lane].offer(m, lane == 2)
	if replaced || !accepted {
		c.dropped.Add(1)
	}
	if !accepted {
		if critical {
			c.resync.Store(true)
			select {
			case c.reset <- struct{}{}:
			default:
			}
		}
		return false
	}
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return true
}
func (c *Client) status(v bool) {
	c.connected.Store(v)
	select {
	case c.Status <- v:
	default:
	}
}
func (c *Client) Run(ctx context.Context) {
	defer func() {
		if c.reportEncoder != nil {
			_ = c.reportEncoder.Close()
			c.reportEncoder = nil
		}
	}()
	backoff := time.Second
	for ctx.Err() == nil {
		if c.connect(ctx) {
			backoff = time.Second
		} else {
			backoff = min(60*time.Second, backoff*2)
		}
		timer := time.NewTimer(time.Duration(float64(backoff) * (0.75 + rand.Float64()*0.5)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
