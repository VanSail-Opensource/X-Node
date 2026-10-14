// Package transport owns the agent's single WebSocket and serialized writer.
package transport

import (
	"context"
	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/gorilla/websocket"
	"math/rand/v2"
	"net/http"
	"sync/atomic"
	"time"
)

type Client struct {
	URL       string
	Token     string
	Dialer    *websocket.Dialer
	Hello     func() protocol.Message
	Incoming  chan protocol.Message
	Status    chan bool
	high      chan protocol.Message
	low       chan protocol.Message
	reset     chan struct{}
	connected atomic.Bool
	resync    atomic.Bool
	dropped   atomic.Uint64
}

func New(url, token string) *Client {
	return &Client{URL: url, Token: token, Incoming: make(chan protocol.Message, 128), Status: make(chan bool, 8), high: make(chan protocol.Message, 64), low: make(chan protocol.Message, 64), reset: make(chan struct{}, 1)}
}
func (c *Client) Connected() bool { return c.connected.Load() }
func (c *Client) Dropped() uint64 { return c.dropped.Load() }
func (c *Client) Send(m protocol.Message, critical bool) bool {
	queue := c.low
	if critical {
		queue = c.high
	}
	select {
	case queue <- m:
		return true
	default:
		c.dropped.Add(1)
		if critical {
			c.resync.Store(true)
			select {
			case c.reset <- struct{}{}:
			default:
			}
		}
		return false
	}
}
func (c *Client) status(v bool) {
	c.connected.Store(v)
	select {
	case c.Status <- v:
	default:
	}
}
func (c *Client) Run(ctx context.Context) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		connected := c.connect(ctx)
		if connected {
			backoff = time.Second
		} else {
			backoff = min(60*time.Second, backoff*2)
		}
		delay := time.Duration(float64(backoff) * (0.75 + rand.Float64()*0.5))
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (c *Client) connect(ctx context.Context) bool {
	dialer := c.Dialer
	if dialer == nil {
		copy := *websocket.DefaultDialer
		copy.HandshakeTimeout = 15 * time.Second
		dialer = &copy
	}
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+c.Token)
	headers.Set("Sec-WebSocket-Protocol", "x-node.v1")
	socket, response, e := dialer.DialContext(ctx, c.URL, headers)
	if e != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		nlog.Core().Warn("master connection failed")
		return false
	}
	defer socket.Close()
	defer c.status(false)
	socket.SetReadLimit(protocol.MaxFrameBytes)
	_ = socket.SetReadDeadline(time.Now().Add(90 * time.Second))
	socket.SetPongHandler(func(string) error { return socket.SetReadDeadline(time.Now().Add(90 * time.Second)) })
	pong := make(chan string, 8)
	socket.SetPingHandler(func(data string) error {
		select {
		case pong <- data:
		default:
		}
		return nil
	})
	write := func(m protocol.Message) error {
		_ = socket.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return socket.WriteJSON(m)
	}
	if c.Hello != nil {
		if write(c.Hello()) != nil {
			return true
		}
	}
	if write(protocol.New("state.request", "", 0, map[string]string{"reason": "connected"})) != nil {
		return true
	}
	c.status(true)
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			kind, b, e := socket.ReadMessage()
			if e != nil {
				return
			}
			_ = socket.SetReadDeadline(time.Now().Add(90 * time.Second))
			if kind != websocket.TextMessage {
				c.resync.Store(true)
				continue
			}
			m, e := protocol.Parse(b)
			if e != nil {
				c.resync.Store(true)
				continue
			}
			select {
			case c.Incoming <- m:
			case <-child.Done():
				return
			default:
				c.resync.Store(true)
			}
		}
	}()
	defer func() { cancel(); socket.Close(); <-done }()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	check := time.NewTicker(250 * time.Millisecond)
	defer check.Stop()
	for {
		// Replies and acknowledged traffic take precedence over disposable snapshots.
		select {
		case m := <-c.high:
			if write(m) != nil {
				return true
			}
			continue
		default:
		}
		select {
		case <-ctx.Done():
			return true
		case <-done:
			return true
		case <-c.reset:
			return true
		case m := <-c.high:
			if write(m) != nil {
				return true
			}
		case m := <-c.low:
			if write(m) != nil {
				return true
			}
		case p := <-pong:
			if socket.WriteControl(websocket.PongMessage, []byte(p), time.Now().Add(5*time.Second)) != nil {
				return true
			}
		case <-ping.C:
			if socket.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)) != nil {
				return true
			}
		case <-check.C:
			if c.resync.Swap(false) {
				if write(protocol.New("state.request", "", 0, map[string]string{"reason": "gap_or_overflow"})) != nil {
					return true
				}
			}
		}
	}
}
