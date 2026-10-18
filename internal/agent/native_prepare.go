package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/VanSail-Opensource/X-Node/internal/geodata"
	"github.com/VanSail-Opensource/X-Node/internal/kernel/xray"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func assetKey(c protocol.Config, p geodata.Policy) string {
	raw, _ := json.Marshal([]any{p, c.AssetHashes})
	return string(raw)
}

// prepareNative is shared by activation and read-only command validation.
// The caller owns nativeMu; no process-global environment is changed.
func (a *Agent) prepareNative(ctx, lifetime context.Context, c protocol.Config, p geodata.Policy) (protocol.Config, string, error) {
	target := a.geoCandidate
	var err error
	if target == "" || a.geoCandidateKey != assetKey(c, p) {
		target, err = a.ensureAssets(ctx, c, p, false)
		if err != nil {
			return c, "", fmt.Errorf("prepare domain assets: %w", err)
		}
	}
	resolved, err := a.Certificates.Prepare(lifetime, c)
	if err != nil {
		return c, "", err
	}
	if err = ctx.Err(); err != nil {
		return c, "", err
	}
	var native map[string]any
	if err = json.Unmarshal(resolved.Xray, &native); err != nil {
		return c, "", err
	}
	env, _ := native["env"].(map[string]any)
	if env == nil {
		env = map[string]any{}
	}
	env["XRAY_LOCATION_ASSET"] = target
	native["env"] = env
	resolved.Xray, err = json.Marshal(native)
	if err != nil {
		return c, "", err
	}
	if _, err = xray.Prepare(resolved); err != nil {
		return c, "", err
	}
	return resolved, target, nil
}
