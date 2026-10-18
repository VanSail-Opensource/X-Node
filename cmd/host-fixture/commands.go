package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Disposable fixtures retain stderr so kernel and packet failures are actionable.
type fixtureRunner struct{}

func (fixtureRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	started := time.Now()
	b, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	// Only utility names and durations are logged; arguments may contain secrets.
	fmt.Fprintf(os.Stderr, "fixture utility %s finished after %s (context: %v)\n", name, time.Since(started).Round(time.Millisecond), ctx.Err())
	if err != nil {
		return b, fmt.Errorf("%s: %w: %s", name, err, b)
	}
	return b, nil
}
