package transport

import (
	"context"
	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/gorilla/websocket"
	"net/http"
	"time"
)

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
	return c.writeLoop(ctx, socket, done, pong, write)
}
