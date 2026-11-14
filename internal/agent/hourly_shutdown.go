package agent

import (
	"context"
	"errors"
	"sync"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
)

// The gate and WaitGroup share this mutex so shutdown cannot race a new Add
// after it starts waiting. Only durable command work needs joining: native
// delivery completion cannot change counters already consumed by Permit.Begin.
func (h *hourlyRuntime) beginOperation() bool {
	h.operationMu.Lock()
	defer h.operationMu.Unlock()
	if h.stopping.Load() {
		return false
	}
	h.operations.Add(1)
	return true
}

func (a *Agent) shutdownHourly(ctx context.Context, workers *sync.WaitGroup) error {
	h := a.hourly
	h.operationMu.Lock()
	h.stopping.Store(true)
	h.operationMu.Unlock()
	done := make(chan error, 1)
	go func() {
		h.controller.StopAdmission()
		workers.Wait()
		h.operations.Wait()
		err := h.sealStoppedCredits(ctx)
		err = errors.Join(err, h.store.Close())
		// A transport session callback can wait for a native interrupt hook.
		// It follows durable cleanup and remains inside the bounded outer wait.
		a.Client.SetHourlyEnabled(false)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// A filesystem barrier already in progress cannot be cancelled. The
		// fenced worker may finish it, but timeout never reports durable success.
		// Any reservation left unsealed retains normal hard-crash recovery.
		return ctx.Err()
	}
}

func (h *hourlyRuntime) sealStoppedCredits(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !h.store.Healthy() {
		return hourly.ErrCreditUnavailable
	}
	ids := h.controller.CreditIDs()
	if len(ids) == 0 {
		return nil
	}
	candidates := make([]hourly.SealCandidate, 0, len(ids))
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		drain, err := h.controller.FreezeCredit(id)
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-drain.Done():
		}
		candidate, err := h.controller.PrepareSeal(drain)
		if err != nil {
			return err
		}
		candidates = append(candidates, candidate)
	}
	proofs, err := h.store.SealBatch(ctx, candidates)
	if err != nil {
		return err
	}
	for _, proof := range proofs {
		if err := h.controller.ForgetCredit(proof); err != nil {
			return err
		}
		h.forgetInstalledCredit(proof.Install.ReservationID)
	}
	return nil
}
