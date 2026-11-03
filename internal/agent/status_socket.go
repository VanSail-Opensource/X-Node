package agent

import (
	"context"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/localstatus"
)

func (a *Agent) listenStatus(ctx context.Context) (*localstatus.Server, error) {
	return localstatus.Listen(ctx, a.Dir, func() localstatus.Snapshot {
		d := a.Store.Metadata()
		return localstatus.Snapshot{Liveness: true, Ready: a.Runtime.Ready(), Connected: a.Client.Connected(),
			Revision: d.Revision, ConfigRevision: d.ConfigRevision, Updated: time.Now().UTC()}
	})
}
