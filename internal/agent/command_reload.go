package agent

import (
	"context"
	"errors"

	"github.com/VanSail-Opensource/X-Node/internal/cert"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type reloadRequest struct {
	Certificate      *cert.Candidate
	ExpectedRevision uint64
	ID               string
	Done             chan error
	Context          context.Context
	RefreshAssets    bool
	Force            bool
}

// Only the actor reads desired state or schedules material activation.
func (a *Agent) handleReloadRequest(request reloadRequest) {
	if err := request.Context.Err(); err != nil {
		finishReload(request.Done, err)
		return
	}
	if !a.hasDesired {
		finishReload(request.Done, errors.New("full baseline required before reload"))
		return
	}
	if target := request.Certificate; target != nil {
		key, ok := cert.ProfileKey(a.desired, target.ProfileID)
		if !ok || key != target.Key || request.ExpectedRevision != a.Store.Revision() {
			finishReload(request.Done, errors.New("CERTIFICATE_SUPERSEDED"))
			return
		}
		if a.Certificates.ServingMatches(*target) && a.Runtime.Ready() && a.Store.Metadata().ConfigRevision == request.ExpectedRevision {
			a.Certificates.Completed(*target)
			finishReload(request.Done, nil)
			return
		}
	}
	a.queue(request.Context, applyJob{ID: request.ID, Revision: a.Store.Revision(), Config: protocol.Clone(a.desired), Cached: a.desiredCached, ForceRebuild: request.Force, RefreshAssets: request.RefreshAssets, RecheckMaterial: true, Done: request.Done, Certificate: request.Certificate})
}

type reloadOptions struct{ RefreshAssets, Force bool }

func finishReload(done chan error, err error) {
	if done != nil {
		select {
		case done <- err:
		default:
		}
	}
}

// Waiting utility jobs never block the actor or traffic acknowledgments. The
// actor owns supersession, and publishes completion after the activation result.
func (a *Agent) reloadRuntime(ctx context.Context, id string, options ...reloadOptions) (any, error) {
	name := "runtime.reload"
	settings := reloadOptions{}
	if len(options) > 0 {
		settings = options[0]
	}
	if settings.RefreshAssets {
		name = "geodata.refresh"
	}
	child, cancel := context.WithTimeout(ctx, protocol.CommandTimeout(name))
	defer cancel()
	done := make(chan error, 1)
	select {
	case a.notify <- reloadRequest{ID: id, Done: done, Context: child, RefreshAssets: settings.RefreshAssets, Force: settings.Force}:
	case <-child.Done():
		return nil, child.Err()
	}
	select {
	case err := <-done:
		if err != nil {
			return nil, err
		}
		return map[string]bool{"applied": true, "ready": a.Runtime.Ready()}, nil
	case <-child.Done():
		return nil, child.Err()
	}
}
