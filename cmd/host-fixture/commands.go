package main

import (
	"context"
	"fmt"
	"os/exec"
)

// Disposable fixtures retain stderr so kernel and packet failures are actionable.
type fixtureRunner struct{}

func (fixtureRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	b, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return b, fmt.Errorf("%s: %w: %s", name, err, b)
	}
	return b, nil
}
