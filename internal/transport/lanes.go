package transport

import (
	"sync"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// A lane bounds retained payload bytes as well as frame count. Telemetry is a
// replaceable snapshot; traffic is an ordered projection of the durable journal.
type messageLane struct {
	mu       sync.Mutex
	frames   []protocol.Message
	bytes    int
	capacity int
	limit    int
}

func newMessageLane(capacity, limit int) *messageLane {
	return &messageLane{capacity: capacity, limit: limit}
}

func (q *messageLane) offer(m protocol.Message, replace bool) (bool, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	size := len(m.Data) + 128
	if size > q.limit {
		return false, false
	}
	replaced := replace && len(q.frames) > 0
	if replaced {
		q.frames[0] = m
		q.bytes = size
		return true, true
	}
	if len(q.frames) >= q.capacity || size > q.limit-q.bytes {
		return false, false
	}
	q.frames = append(q.frames, m)
	q.bytes += size
	return true, false
}

func (q *messageLane) take() (protocol.Message, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.frames) == 0 {
		return protocol.Message{}, false
	}
	m := q.frames[0]
	copy(q.frames, q.frames[1:])
	q.frames[len(q.frames)-1] = protocol.Message{}
	q.frames = q.frames[:len(q.frames)-1]
	q.bytes -= len(m.Data) + 128
	return m, true
}

func (c *Client) next(cursor *int) (protocol.Message, bool) {
	// Two command slots per round keep replies responsive while every report
	// class has a guaranteed turn during continuous command/log production.
	order := [...]int{0, 0, 1, 2, 3}
	for range order {
		lane := order[*cursor]
		*cursor = (*cursor + 1) % len(order)
		if m, ok := c.lanes[lane].take(); ok {
			return m, true
		}
	}
	return protocol.Message{}, false
}
