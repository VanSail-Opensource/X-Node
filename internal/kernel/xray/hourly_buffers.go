package xray

import (
	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/xtls/xray-core/common/buf"
)

func validateHourlyBuffers(mb buf.MultiBuffer, datagram bool) error {
	for _, buffer := range mb {
		if buffer != nil && (datagram || buffer.UDP != nil) && buffer.Len() > protocol.MaxHourlyBurstBytes {
			return hourly.ErrInvalid
		}
	}
	return nil
}

// Empty stream buffers carry no payload. A zero-length UDP buffer is a packet.
func hourlyFront(mb *buf.MultiBuffer, datagram bool) (int, int, bool) {
	for len(*mb) > 0 {
		first := (*mb)[0]
		if first == nil || first.Len() == 0 && !datagram && first.UDP == nil {
			if first != nil {
				first.Release()
			}
			(*mb)[0] = nil
			*mb = (*mb)[1:]
			continue
		}
		want := int(first.Len())
		if datagram || first.UDP != nil {
			return want, want, true
		}
		return min(want, protocol.MaxHourlyBurstBytes), 1, true
	}
	return 0, 0, false
}

// Take exactly the admitted bytes. Upstream SplitSize can return a shorter
// prefix and strips UDP metadata when splitting, so it cannot implement this.
func takeHourlyBuffer(mb *buf.MultiBuffer, n int) buf.MultiBuffer {
	first := (*mb)[0]
	if n == int(first.Len()) {
		(*mb)[0] = nil
		*mb = (*mb)[1:]
		return buf.MultiBuffer{first}
	}
	head := buf.NewWithSize(int32(n))
	copy(head.Extend(int32(n)), first.BytesTo(int32(n)))
	first.Advance(int32(n))
	return buf.MultiBuffer{head}
}
