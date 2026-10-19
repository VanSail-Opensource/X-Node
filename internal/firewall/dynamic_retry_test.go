package firewall

import (
	"context"
	"errors"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type dynamicRetryKernel struct{ *guardKernel }

func (k *dynamicRetryKernel) Bans(ctx context.Context, bans []protocol.FirewallBan, grants []protocol.FirewallExemption, sources []protocol.FirewallSource, replace bool) error {
	if replace {
		return errors.New("bulk staging is blocked")
	}
	return k.guardKernel.Bans(ctx, bans, grants, sources, false)
}

func TestDynamicSnapshotRetryDoesNotWaitForDirtyBulkSources(t *testing.T) {
	g, kernel := guardFixture(t)
	g.manager.Backend = &dynamicRetryKernel{kernel}
	g.state.MasterVersion, g.state.SnapshotID = 7, "committed"
	g.dirty, g.sourcesDirty = true, true
	if err := g.Sync(context.Background(), protocol.FirewallUpdate{Version: 7, SnapshotID: "committed", Final: true}); err != nil {
		t.Fatal("dynamic replay attempted bulk preparation", err)
	}
	if g.dirty || !g.sourcesDirty {
		t.Fatal("dynamic replay changed independent source dirty state")
	}
}
