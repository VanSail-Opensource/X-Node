package xray

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"google.golang.org/protobuf/proto"
)

func receiverChanged(old, next *Prepared) bool {
	for tag, in := range next.Inbounds {
		if previous := old.Inbounds[tag]; previous != nil && !proto.Equal(previous.ReceiverSettings, in.ReceiverSettings) {
			return true
		}
	}
	return false
}

// Use effective receivers, with compiled certificate bytes, so unrelated
// user or policy updates cannot replay an already disruptive failed cutover.
func receiverKey(p *Prepared) ([32]byte, error) {
	data := &core.Config{}
	for _, tag := range slices.Sorted(maps.Keys(p.Inbounds)) {
		in := p.Inbounds[tag]
		data.Inbound = append(data.Inbound, &core.InboundHandlerConfig{Tag: in.Tag, ReceiverSettings: in.ReceiverSettings})
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(data)
	return sha256.Sum256(raw), err
}

func (r *Runtime) reloadReceivers(lifetime, operation context.Context, next *Prepared, retry bool, restoreEnv func()) error {
	key, err := receiverKey(next)
	if err != nil {
		return err
	}
	if !retry && key == r.failedReceiverKey {
		return errors.New("receiver cutover already failed; use runtime.reload to retry after correcting the listener")
	}
	if err := r.preflightReceiverReload(operation, next); err != nil {
		return err
	}
	previous := r.current
	replacement, recovery := compiledRuntime(next), compiledRuntime(previous)
	if err := operation.Err(); err != nil {
		return err
	}
	// NewWithContext installs the process-global Xray DNS and outbound
	// features. Never construct a second core alongside the serving one.
	started := time.Now()
	defer func() {
		r.stats.ListenerGapMicros = time.Since(started).Microseconds()
		r.stats.ListenerGapMillis = r.stats.ListenerGapMicros / 1000
	}()
	r.stopInstance()
	if err := r.startCompiled(lifetime, next, replacement); err != nil {
		activation := fmt.Errorf("Xray receiver reload failed: %w", err)
		r.failedReceiverKey = key
		// Keep the old protobuf, not its source files. A renewal may have
		// already overwritten those files with a different certificate.
		restoreEnv()
		if recoveryErr := r.startCompiled(lifetime, previous, recovery); recoveryErr != nil {
			return errors.Join(activation, fmt.Errorf("previous Xray runtime could not be restored: %w", recoveryErr))
		}
		r.recordStart(previous, "receiver_rollback")
		return fmt.Errorf("%w (previous runtime restored)", activation)
	}
	r.failedReceiverKey = [32]byte{}
	r.recordStart(next, "receiver_reload")
	return nil
}

// Prepare features against the active core without publishing them. This also
// keeps unrelated transitions which are not supported live from implicitly
// bypassing their validation in a mixed receiver revision.
func (r *Runtime) preflightReceiverReload(ctx context.Context, next *Prepared) error {
	if blocker := outboundReloadBlocker(r.current, next); blocker != "" {
		return fmt.Errorf("%w: %s", ErrReloadUnsupported, blocker)
	}
	features, err := prepareFeatureReload(r.instance, r.current, next)
	if err != nil {
		return err
	}
	defer features.Discard()
	outbounds, err := r.prepareOutboundUpdate(next)
	if err != nil {
		return err
	}
	defer outbounds.abort()
	routes, err := r.prepareRoutingUpdate(next, false)
	if err != nil {
		return err
	}
	defer routes.abort()

	active := make([]*proxyman.ReceiverConfig, 0, len(r.current.Inbounds))
	for _, cfg := range r.current.Core.Inbound {
		receiver, err := synchronousReceiver(cfg)
		if err != nil {
			return err
		}
		active = append(active, receiver)
	}
	for _, cfg := range next.Core.Inbound {
		if err := ctx.Err(); err != nil {
			return err
		}
		receiver, err := synchronousReceiver(cfg)
		if err != nil {
			return err
		}
		old := r.current.Inbounds[cfg.Tag]
		if old != nil && proto.Equal(old.ReceiverSettings, cfg.ReceiverSettings) {
			continue
		}
		overlap := false
		for _, serving := range active {
			if endpointOverlap(receiver, serving) {
				overlap = true
				break
			}
		}
		// Never bind across a live receiver. The native Hysteria validator
		// is tied to its concrete proxy and cannot use the admission gate.
		auxiliary := next.Auxiliary[cfg.Tag]
		if overlap || !auxiliary && cfg.ProxySettings.Type != serial.GetMessageType(&InboundConfig{}) {
			continue
		}
		if err := r.probeNewReceiver(cfg, auxiliary); err != nil {
			return fmt.Errorf("native inbound %q could not stage its listener: %w", cfg.Tag, err)
		}
	}
	return nil
}

func synchronousReceiver(cfg *core.InboundHandlerConfig) (*proxyman.ReceiverConfig, error) {
	receiver, err := receiverSettings(cfg)
	if err != nil {
		return nil, err
	}
	if receiver.GetStreamSettings().GetProtocolName() == "grpc" {
		return nil, fmt.Errorf("%w: native inbound %q has asynchronous gRPC listener startup", ErrReloadUnsupported, cfg.Tag)
	}
	return receiver, nil
}

func (r *Runtime) probeNewReceiver(cfg *core.InboundHandlerConfig, auxiliary bool) error {
	gate := &inboundGate{tag: cfg.Tag, auxiliary: auxiliary, ready: make(chan struct{})}
	handler, err := r.newStagedInbound(cfg, gate)
	if err != nil {
		return err
	}
	err = handler.Start()
	close(gate.ready)
	return errors.Join(err, handler.Close())
}
