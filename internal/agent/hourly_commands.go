package agent

import (
	"context"
	"errors"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (a *Agent) hourlyCommand(ctx context.Context, name string, args []byte) (any, error) {
	if !a.checkHourlyHealth() || !a.Client.Hourly() {
		return nil, refuseJob(hourly.ErrUnavailable)
	}
	h := a.hourly
	defer a.checkHourlyHealth()
	switch name {
	case protocol.HourlyCreditInstallCommand:
		var install protocol.HourlyCreditInstall
		if err := protocol.Decode(args, &install); err != nil {
			return nil, refuseJob(err)
		}
		if err := protocol.ValidateHourlyInstall(install); err != nil {
			return nil, refuseJob(err)
		}
		if install.AgentID != a.Store.Metadata().AgentID || install.BootID != a.BootID || install.SessionID != a.Client.HourlySession() {
			return nil, refuseJob(errors.New("hourly credit does not match current agent session"))
		}
		credit, err := h.store.Install(ctx, install)
		if err != nil {
			if errors.Is(err, hourly.ErrCreditReplay) || errors.Is(err, hourly.ErrCreditScope) {
				return nil, refuseJob(err)
			}
			return nil, err
		}
		h.creditMu.Lock()
		h.installed[install.ReservationID] = install
		h.creditMu.Unlock()
		if err = h.controller.InstallCredit(credit); err != nil {
			h.forgetInstalledCredit(install.ReservationID)
			// The one-shot unclaimed marker proves no payload could consume it.
			if _, sealErr := h.store.SealUnclaimed(context.WithoutCancel(ctx), credit); sealErr != nil {
				return nil, sealErr
			}
			return nil, refuseJob(err)
		}
		return map[string]bool{"installed": true}, nil
	case protocol.HourlyCreditSealCommand:
		var seal protocol.HourlyCreditSeal
		if err := protocol.Decode(args, &seal); err != nil {
			return nil, refuseJob(err)
		}
		if !protocol.ValidName(seal.ReservationID) {
			return nil, refuseJob(hourly.ErrInvalid)
		}
		return a.sealHourlyCommand(ctx, seal)
	case protocol.HourlyCreditAckCommand:
		var ack protocol.HourlyCreditAck
		if err := protocol.Decode(args, &ack); err != nil {
			return nil, refuseJob(err)
		}
		if err := h.store.Ack(ctx, ack); err != nil {
			return nil, err
		}
		h.forgetInstalledCredit(ack.ReservationID)
		return map[string]bool{"acknowledged": true}, nil
	}
	return nil, hourly.ErrInvalid
}

// Store/controller operations are independently idempotent. No global runtime
// lock is held while waiting for an individual native handoff barrier.
func (h *hourlyRuntime) sealCredit(ctx context.Context, id string) (protocol.HourlyCreditProof, error) {
	for _, proof := range h.store.Recovery() {
		if proof.Install.ReservationID == id {
			if !proof.Recovery {
				if err := h.controller.ForgetCredit(proof); err != nil {
					return protocol.HourlyCreditProof{}, err
				}
				h.forgetInstalledCredit(id)
			}
			return proof, nil
		}
	}
	drain, err := h.controller.FreezeCredit(id)
	if err != nil {
		return protocol.HourlyCreditProof{}, err
	}
	select {
	case <-ctx.Done():
		return protocol.HourlyCreditProof{}, ctx.Err()
	case <-drain.Done():
	}
	candidate, err := h.controller.PrepareSeal(drain)
	if err != nil {
		return protocol.HourlyCreditProof{}, err
	}
	proof, err := h.store.Seal(ctx, candidate)
	if err != nil {
		return protocol.HourlyCreditProof{}, err
	}
	if err = h.controller.ForgetCredit(proof); err != nil {
		return protocol.HourlyCreditProof{}, err
	}
	h.forgetInstalledCredit(id)
	return proof, nil
}

func (h *hourlyRuntime) forgetInstalledCredit(id string) {
	h.creditMu.Lock()
	delete(h.installed, id)
	h.creditMu.Unlock()
}
