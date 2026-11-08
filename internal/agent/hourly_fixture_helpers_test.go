package agent

import (
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Progress-only batches and already-sent old nonces can precede a fresh demand.
// Match the actual owner/nonce rather than assuming the next frame has a grant.
func (f *hourlyAgentFixture) demand(t *testing.T, peer *hourlyTestPeer, previousNonce string) protocol.HourlyDemand {
	t.Helper()
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	for {
		select {
		case event := <-f.frames:
			if event.peer != peer || event.message.Type != "hourly.demand" {
				continue
			}
			var batch protocol.HourlyDemandBatch
			if err := protocol.Decode(event.message.Data, &batch); err != nil {
				t.Fatal(err)
			}
			for _, demand := range batch.Demands {
				if demand.Owner == f.config.Users[0].Hourly.Owner && demand.Nonce != previousNonce {
					return demand
				}
			}
		case <-timer.C:
			t.Fatal("fresh hourly owner demand did not arrive")
			return protocol.HourlyDemand{}
		}
	}
}
