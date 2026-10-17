package firewall

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// MonitorKernel uses the Linux NFLOG UAPI. Only the first 32 packet bytes are
// copied; payloads are never logged, stored, or sent to the master.
func (g *Guard) MonitorKernel(ctx context.Context) error {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	if err = c.SetReadBuffer(4 << 20); err != nil {
		return err
	}
	mode := make([]byte, 6)
	binary.BigEndian.PutUint32(mode, 32)
	mode[4] = 2
	attributes, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: 1, Data: []byte{1}}, {Type: 2, Data: mode}, {Type: 6, Data: []byte{0, 1}}})
	if err != nil {
		return err
	}
	header := []byte{unix.AF_UNSPEC, 0, 0, 0}
	binary.BigEndian.PutUint16(header[2:], nfLogGroup)
	if _, err = c.Execute(netlink.Message{Header: netlink.Header{Type: netlink.HeaderType((unix.NFNL_SUBSYS_ULOG << 8) | 1), Flags: netlink.Request | netlink.Acknowledge}, Data: append(header, attributes...)}); err != nil {
		return err
	}
	g.kernelReady.Store(true)
	defer g.kernelReady.Store(false)
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	var sequence uint32
	for {
		messages, err := c.Receive()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, unix.ENOBUFS) {
				g.dropped.Add(1)
				continue
			}
			return err
		}
		for _, message := range messages {
			if len(message.Data) < 4 || uint16(message.Header.Type)>>8 != unix.NFNL_SUBSYS_ULOG {
				continue
			}
			decoder, err := netlink.NewAttributeDecoder(message.Data[4:])
			if err != nil {
				g.dropped.Add(1)
				continue
			}
			var payload []byte
			var rule string
			for decoder.Next() {
				switch decoder.Type() {
				case 9:
					payload = append([]byte(nil), decoder.Bytes()...)
				case 10:
					rule = strings.TrimRight(string(decoder.Bytes()), "\x00")
				case 12:
					value := decoder.Bytes()
					if len(value) == 4 {
						next := binary.BigEndian.Uint32(value)
						if sequence != 0 && next > sequence+1 {
							g.dropped.Add(uint64(next - sequence - 1))
						}
						sequence = next
					}
				}
			}
			if decoder.Err() != nil || !strings.HasPrefix(rule, "x-node:") {
				continue
			}
			ip, ok := packetSource(payload)
			if ok {
				g.Observe(ip, strings.TrimPrefix(rule, "x-node:"))
			}
		}
	}
}
func packetSource(packet []byte) (netip.Addr, bool) {
	if len(packet) >= 16 && packet[0]>>4 == 4 {
		var raw [4]byte
		copy(raw[:], packet[12:16])
		return netip.AddrFrom4(raw), true
	}
	if len(packet) >= 24 && packet[0]>>4 == 6 {
		var raw [16]byte
		copy(raw[:], packet[8:24])
		return netip.AddrFrom16(raw), true
	}
	return netip.Addr{}, false
}
func (g *Guard) RunKernel(ctx context.Context) {
	for ctx.Err() == nil {
		_ = g.MonitorKernel(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			g.dropped.Add(1)
		}
	}
}
