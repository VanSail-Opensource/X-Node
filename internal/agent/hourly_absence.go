package agent

import (
	"context"
	"errors"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (a *Agent) sealHourlyCommand(ctx context.Context, seal protocol.HourlyCreditSeal) (protocol.HourlyCreditProof, error) {
	if err := protocol.ValidateHourlySeal(seal); err != nil {
		return protocol.HourlyCreditProof{}, refuseJob(err)
	}
	if expected := seal.Expected; expected != nil {
		if protocol.ValidateHourlyInstall(*expected) != nil || expected.ReservationID != seal.ReservationID || expected.AgentID != a.Store.Metadata().AgentID {
			return protocol.HourlyCreditProof{}, refuseJob(hourly.ErrInvalid)
		}
		a.hourly.creditMu.Lock()
		installed, known := a.hourly.installed[seal.ReservationID]
		a.hourly.creditMu.Unlock()
		if known && installed != *expected {
			return protocol.HourlyCreditProof{}, refuseJob(hourly.ErrCreditScope)
		}
	}
	proof, err := a.hourly.sealCredit(ctx, seal.ReservationID)
	if err == nil && seal.Expected != nil && proof.Install != *seal.Expected {
		return protocol.HourlyCreditProof{}, refuseJob(hourly.ErrCreditScope)
	}
	if !errors.Is(err, hourly.ErrInvalid) || seal.Expected == nil {
		return proof, err
	}
	// The store's bounded sequence evidence, not a missing connection, proves
	// whether this exact obligation was never issued. It fences any later install.
	proof, err = a.hourly.store.SealAbsent(ctx, *seal.Expected)
	if err == nil {
		a.hourly.forgetInstalledCredit(seal.ReservationID)
	}
	return proof, err
}
