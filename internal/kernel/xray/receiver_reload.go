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

// Use effective receivers, including compiled certificate bytes.
func receiverKey(p *Prepared) ([32]byte, error) {
	data := &core.Config{}
	for _, tag := range slices.Sorted(maps.Keys(p.Inbounds)) {
		in := p.Inbounds[tag]
		data.Inbound = append(data.Inbound, &core.InboundHandlerConfig{Tag: in.Tag, ReceiverSettings: in.ReceiverSettings})
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(data)
	return sha256.Sum256(raw), err
}

func coldReloadKey(p *Prepared) ([32]byte, error) {
	receivers, err := receiverKey(p)
	if err != nil {
		return [32]byte{}, err
	}
	outbounds := make(map[string][32]byte, len(p.Outbounds))
	for tag := range p.Outbounds {
		outbounds[tag] = p.Keys["out:"+tag]
	}
	// Exclude authorization/user churn. Include the parts of the native
	// candidate that can actually fix a startup failure.
	return sectionKey([]any{receivers, p.StaticHash, p.InboundBase, p.Keys["routing"], outbounds, defaultOutboundTag(p)}), nil
}

func (r *Runtime) reloadCold(lifetime, operation context.Context, next *Prepared, retry bool, restoreEnv func(), mode string) error {
	key, err := coldReloadKey(next)
	if err != nil {
		return err
	}
	if !retry && key == r.failedColdKey {
		return errors.New("cold cutover already failed; use runtime.reload to retry after correcting the configuration")
	}
	if err := r.preflightReceiverReload(operation, next); err != nil {
		return err
	}
	previous := r.current
	replacement, err := compiledRuntime(next)
	if err != nil {
		return err
	}
	recovery, err := compiledRuntime(previous)
	if err != nil {
		return err
	}
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
		activation := fmt.Errorf("Xray %s reload failed: %w", mode, err)
		r.failedColdKey = key
		// Keep the old protobuf, not its source files. A renewal may have
		// already overwritten those files with a different certificate.
		restoreEnv()
		if recoveryErr := r.startCompiled(lifetime, previous, recovery); recoveryErr != nil {
			return errors.Join(activation, fmt.Errorf("previous Xray runtime could not be restored: %w", recoveryErr))
		}
		r.recordStart(previous, mode+"_rollback")
		return fmt.Errorf("%w (previous runtime restored)", activation)
	}
	r.failedColdKey = [32]byte{}
	r.recordStart(next, mode+"_reload")
	return nil
}

// The candidate has already passed native validation. Probe disjoint listeners
// where possible without attempting to stage the unsupported live transition.
func (r *Runtime) preflightReceiverReload(ctx context.Context, next *Prepared) error {
	active := make([]*proxyman.ReceiverConfig, 0, len(r.current.Inbounds))
	for _, cfg := range r.current.Core.Inbound {
		receiver, err := receiverSettings(cfg)
		if err != nil {
			return err
		}
		active = append(active, receiver)
	}
	for _, cfg := range next.Core.Inbound {
		if err := ctx.Err(); err != nil {
			return err
		}
		receiver, err := receiverSettings(cfg)
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
		probe := proto.Clone(cfg).(*core.InboundHandlerConfig)
		if err := enableSynchronousGRPC(probe); err != nil {
			return err
		}
		if err := r.probeNewReceiver(probe, auxiliary); err != nil {
			return fmt.Errorf("native inbound %q could not stage its listener: %w", cfg.Tag, err)
		}
	}
	return nil
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
