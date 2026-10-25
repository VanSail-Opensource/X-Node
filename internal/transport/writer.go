package transport

import (
	"context"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/gorilla/websocket"
)

func (c *Client) writeLoop(ctx context.Context, socket *websocket.Conn, done <-chan struct{}, pong <-chan string, write func(protocol.Message) error) bool {
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	check := time.NewTicker(250 * time.Millisecond)
	defer check.Stop()
	control := func(kind int, payload string) bool {
		return socket.WriteControl(kind, []byte(payload), time.Now().Add(5*time.Second)) != nil
	}
	resync := func() bool {
		return c.resync.Swap(false) && write(protocol.New("state.request", "", 0, map[string]string{"reason": "gap_or_overflow"})) != nil
	}
	cursor := 0
	for {
		// Control frames cannot wait behind a continuously populated data lane.
		select {
		case <-ctx.Done():
			return true
		case <-done:
			return true
		case <-c.reset:
			return true
		case p := <-pong:
			if control(websocket.PongMessage, p) {
				return true
			}
		case <-ping.C:
			if control(websocket.PingMessage, "") {
				return true
			}
		case <-check.C:
			if resync() {
				return true
			}
		default:
		}
		if m, ok := c.next(&cursor); ok {
			if write(m) != nil {
				return true
			}
			continue
		}
		select {
		case <-ctx.Done():
			return true
		case <-done:
			return true
		case <-c.reset:
			return true
		case <-c.wake:
		case p := <-pong:
			if control(websocket.PongMessage, p) {
				return true
			}
		case <-ping.C:
			if control(websocket.PingMessage, "") {
				return true
			}
		case <-check.C:
			if resync() {
				return true
			}
		}
	}
}
