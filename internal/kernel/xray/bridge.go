package xray

import (
	"context"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"

	"github.com/VanSail-Opensource/X-Node/internal/sessions"
)

type bridgeKey struct{}
type leaseKey struct{}
type integration struct {
	Observe     func(InboundObservation)
	Registry    *sessions.Registry
	BanNanos    atomic.Int64
	stopping    atomic.Bool
	Auxiliary   atomic.Pointer[map[string]bool]
	inboundGate atomic.Pointer[inboundGate]
}
type managedOutbound struct {
	outbound.Handler
	bridge   *integration
	lifetime *outboundLifetime
}

func (h *managedOutbound) SenderSettings() *serial.TypedMessage {
	settings := h.Handler.SenderSettings()
	runtime.KeepAlive(h)
	return settings
}

func (h *managedOutbound) ProxySettings() *serial.TypedMessage {
	settings := h.Handler.ProxySettings()
	runtime.KeepAlive(h)
	return settings
}

func (h *managedOutbound) Dispatch(ctx context.Context, link *transport.Link) {
	// Native routing looks up the handler before dispatching. The wrapper
	// remains a lifetime pin from lookup until the concrete handler returns.
	defer func() { runtime.KeepAlive(h) }()
	if h.bridge.stopping.Load() || ctx.Err() != nil {
		_ = common.Interrupt(link.Reader)
		_ = common.Interrupt(link.Writer)
		return
	}
	si := session.InboundFromContext(ctx)
	// Native forwarding attaches a level-only MemoryUser with an empty email.
	if si == nil || si.Tag == coreDNSTag || (si.User == nil || si.User.Email == "") && h.bridge.auxiliaryAllowed(si.Tag) {
		h.Handler.Dispatch(ctx, link)
		return
	}
	if lease, ok := ctx.Value(leaseKey{}).(*sessions.Lease); ok {
		if !lease.TrackOutbound(h.Tag()) {
			common.Interrupt(link.Reader)
			_ = common.Interrupt(link.Writer)
			return
		}
		h.Handler.Dispatch(ctx, link)
		return
	} // Chained outbounds share one reservation.
	reject := func() { _ = common.Interrupt(link.Reader); _ = common.Interrupt(link.Writer) }
	if si.User == nil || !strings.HasPrefix(si.User.Email, "user@") {
		reject()
		return
	}
	identityID, _, _ := strings.Cut(strings.TrimPrefix(si.User.Email, "user@"), ":")
	id, err := strconv.Atoi(identityID)
	if err != nil || id <= 0 {
		reject()
		return
	}
	obs := session.OutboundsFromContext(ctx)
	if len(obs) == 0 {
		reject()
		return
	}
	dest := obs[len(obs)-1].Target
	child, cancel := context.WithCancel(ctx)
	// The copy belongs to this logical flow. Removing Conn disables raw splice without racing the inbound's session object.
	copied := *si
	copied.CanSpliceCopy = 3
	copied.Conn = nil
	child = session.ContextWithInbound(child, &copied)
	connection := si.Conn
	lease, err := h.bridge.Registry.AcquireTrackedWithTransportFence(child, id, si.User.Email, si.Tag, si.Source.Address.IP().String(), dest.NetAddr(), strings.ToLower(dest.Network.String()), int(dest.Port), func() { cancel(); reject() }, func() {
		if connection != nil {
			_ = connection.Close()
		}
	})
	if err != nil {
		cancel()
		reject()
		return
	}
	defer func() { lease.Close(); lease.Finish() }()
	if !lease.TrackOutbound(h.Tag()) {
		return
	}
	child = context.WithValue(child, leaseKey{}, lease)
	if h.Tag() == "_xnode_torrent" {
		h.bridge.Registry.Ban(id, time.Now().Add(time.Duration(h.bridge.BanNanos.Load())))
		return
	}
	stop := context.AfterFunc(child, lease.Close)
	defer stop()
	// These are outbound-facing links. Xray's mux-facing *pipe.Reader is left untouched.
	wrapped := &transport.Link{Reader: &meterReader{Reader: link.Reader, ctx: child, lease: lease}, Writer: &meterWriter{Writer: link.Writer, ctx: child, lease: lease}}
	if flow, hourlyMode := lease.HourlyFlow(); hourlyMode {
		if flow == nil {
			return
		}
		reader := &hourlyReader{Reader: link.Reader, ctx: child, cancel: cancel, lease: lease, acquire: hourlyAcquirer(flow), datagram: lease.Info.Network == "udp"}
		writer := &hourlyWriter{Writer: link.Writer, ctx: child, cancel: cancel, lease: lease, acquire: hourlyAcquirer(flow), datagram: lease.Info.Network == "udp"}
		defer reader.releasePending()
		wrapped = &transport.Link{Reader: reader, Writer: writer}
	}
	h.Handler.Dispatch(child, wrapped)
}

type meterReader struct {
	buf.Reader
	ctx   context.Context
	lease *sessions.Lease
}

func (r *meterReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if len(mb) > 0 {
		n := mb.Len()
		if e := r.lease.Wait(r.ctx, int(n)); e != nil {
			buf.ReleaseMulti(mb)
			return nil, e
		}
		r.lease.Account(true, uint64(n))
	}
	return mb, err
}
func (r *meterReader) Interrupt() { common.Interrupt(r.Reader) }

type meterWriter struct {
	buf.Writer
	ctx   context.Context
	lease *sessions.Lease
}

func (w *meterWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	n := mb.Len()
	if err := w.lease.Wait(w.ctx, int(n)); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}
	err := w.Writer.WriteMultiBuffer(mb)
	if err == nil {
		w.lease.Account(false, uint64(n))
	}
	return err
}
func (w *meterWriter) Close() error { return common.Close(w.Writer) }
