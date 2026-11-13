package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/geodata"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestUnsafeEnvironmentRejectedBeforeAssetsOrCertificates(t *testing.T) {
	c := protocol.Config{Xray: json.RawMessage(`{"env":{"LD_PRELOAD":"/untrusted"}}`)}
	// Deliberately no asset directory, guard or certificate pool: rejection must
	// precede every dependency, including a cached validation proof.
	a := &Agent{validationValid: true}
	if err := a.validateNative(context.Background(), c, geodata.Policy{}); err == nil {
		t.Fatal("validation accepted unsafe environment")
	}
	if _, _, err := a.prepareCertificateNative(context.Background(), context.Background(), c, geodata.Policy{}, false, nil); err == nil {
		t.Fatal("activation accepted unsafe environment")
	}
	if err := a.activate(context.Background(), applyJob{Context: context.Background(), Config: c, RefreshAssets: true}); err == nil {
		t.Fatal("forced asset refresh accepted unsafe environment")
	}
}
