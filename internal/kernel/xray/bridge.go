package xray

import (
	"context"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	nativeoutbound "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"

	"github.com/VanSail-Opensource/X-Node/internal/sessions"
)

type bridgeKey struct{}
type leaseKey struct{}
type integration struct {
	Registry *sessions.Registry
	BanNanos atomic.Int64
}
type managedManager struct {
	outbound.Manager
	bridge *integration
}

func init() {
	common.Must(common.RegisterConfig((*ManagerConfig)(nil), func(ctx context.Context, _ any) (any, error) {
		original, err := nativeoutbound.New(ctx, &proxyman.OutboundConfig{})
		if err != nil {
			return nil, err
		}
		return &managedManager{Manager: original, bridge: ctx.Value(bridgeKey{}).(*integration)}, nil
	}))
}
func (m *managedManager) AddHandler(ctx context.Context, h outbound.Handler) error {
	return m.Manager.AddHandler(ctx, &managedOutbound{Handler: h, bridge: m.bridge})
}

type managedOutbound struct {
	outbound.Handler
	bridge *integration
}

func (h *managedOutbound) Dispatch(ctx context.Context, link *transport.Link) {
	si := session.InboundFromContext(ctx)
	if si == nil || si.Tag == "_xnode_dns" {
		h.Handler.Dispatch(ctx, link)
		return
	}
	if ctx.Value(leaseKey{}) != nil {
		h.Handler.Dispatch(ctx, link)
		return
	} // Chained outbounds share one reservation.
	reject := func() { common.Interrupt(link.Reader); _ = common.Close(link.Writer) }
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
	lease, err := h.bridge.Registry.AcquireTracked(child, id, si.User.Email, si.Tag, si.Source.Address.IP().String(), dest.NetAddr(), strings.ToLower(dest.Network.String()), int(dest.Port), func() { cancel(); reject() })
	if err != nil {
		cancel()
		reject()
		return
	}
	defer func() { lease.Close(); lease.Finish() }()
	child = context.WithValue(child, leaseKey{}, lease)
	if h.Tag() == "_xnode_torrent" {
		h.bridge.Registry.Ban(id, time.Now().Add(time.Duration(h.bridge.BanNanos.Load())))
		return
	}
	stop := context.AfterFunc(child, lease.Close)
	defer stop()
	// These are outbound-facing links. Xray's mux-facing *pipe.Reader is left untouched.
	wrapped := &transport.Link{Reader: &meterReader{Reader: link.Reader, ctx: child, lease: lease}, Writer: &meterWriter{Writer: link.Writer, ctx: child, lease: lease}}
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
		if e := r.lease.Wait(r.ctx, int(mb.Len())); e != nil {
			buf.ReleaseMulti(mb)
			return nil, e
		}
		r.lease.Account(true, uint64(mb.Len()))
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
