package agent

import (
	"context"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type reloadRequest struct {
	ID            string
	Done          chan error
	Context       context.Context
	RefreshAssets bool
}

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
func (a *Agent) reloadRuntime(ctx context.Context, id string, refresh ...bool) (any, error) {
	name := "runtime.reload"
	refreshAssets := len(refresh) > 0 && refresh[0]
	if refreshAssets {
		name = "geodata.refresh"
	}
	child, cancel := context.WithTimeout(ctx, protocol.CommandTimeout(name))
	defer cancel()
	done := make(chan error, 1)
	select {
	case a.notify <- reloadRequest{ID: id, Done: done, Context: child, RefreshAssets: refreshAssets}:
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
