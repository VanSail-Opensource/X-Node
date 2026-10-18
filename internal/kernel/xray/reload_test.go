package xray

import (
	"context"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/sessions"
)

func TestForcedReloadValidatesBeforeStoppingWorkingRuntime(t *testing.T) {
	config, _ := testConfig(t)
	runtime := New(sessions.New())
	defer runtime.Stop()
	if err := runtime.Apply(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	instance := runtime.instance
	invalid := config
	invalid.Xray = []byte(`{"inbounds":false}`)
	if err := runtime.Apply(context.Background(), invalid, true); err == nil || !runtime.Ready() || runtime.instance != instance {
		t.Fatal("invalid reload stopped the working runtime", err)
	}
	if err := runtime.Apply(context.Background(), config, true); err != nil || !runtime.Ready() || runtime.instance == instance {
		t.Fatal("forced reload did not rebuild", err)
	}
}
