package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/update"
)

// The installer can invoke a newly verified CLI while the installed agent is
// older. Comparing against the CLI version would incorrectly skip that upgrade.
func installedUpdater(ctx context.Context, runner host.Runner) (*update.Manager, error) {
	raw, err := runner.Run(ctx, "/usr/local/bin/x-node", "--version")
	if err != nil {
		return nil, errors.New("cannot read installed agent build metadata")
	}
	var metadata struct {
		Version string `json:"version"`
	}
	if len(raw) > 1<<20 || json.Unmarshal(raw, &metadata) != nil || metadata.Version == "" || len(metadata.Version) > 64 {
		return nil, errors.New("invalid installed agent build metadata")
	}
	return update.New("/var/lib/x-node/updates", metadata.Version, runner), nil
}
