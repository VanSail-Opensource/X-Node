package agent

import (
	"context"

	"github.com/VanSail-Opensource/X-Node/internal/geodata"
	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// restoreAcceptedRuntime is a cold-start availability fallback, not another
// activation of the pending revision. It changes neither durable state nor
// registry authorization, and the original failure still triggers a retry.
func (a *Agent) restoreAcceptedRuntime(lifetime context.Context, job applyJob) error {
	if err := a.nativeMu.LockContext(job.Context); err != nil {
		return nil // A superseding activation owns the next attempt.
	}
	defer a.nativeMu.Unlock()
	if a.Runtime.Ready() || a.Store.Revision() != job.Revision {
		return nil
	}
	accepted, ok := a.Store.Configuration()
	if !ok {
		return nil
	}
	// Render the accepted accounts for the accepted listeners. New accounts
	// may refer to different tags or protocols. The current registry still
	// enforces durable revocations and credential identity on every flow.
	policy, err := geodata.FromNative(accepted.Xray)
	if err != nil {
		return err
	}
	candidate, _, err := a.prepareResolved(job.Context, accepted, policy, true, false, func(c protocol.Config) (protocol.Config, error) {
		return a.Certificates.PrepareRetained(job.Context, c)
	})
	if err != nil {
		return err
	}
	if job.Context.Err() != nil || a.Store.Revision() != job.Revision {
		return nil
	}
	if err := a.Runtime.ApplyPreparedContext(lifetime, job.Context, candidate, false); err != nil {
		return err
	}
	a.Certificates.RetainRuntime(accepted, candidate.Source)
	a.systemdReady()
	nlog.Core().Warn("serving last accepted configuration; newer configuration remains pending")
	return nil
}
