package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/VanSail-Opensource/X-Node/internal/cert"
	"github.com/VanSail-Opensource/X-Node/internal/geodata"
	"github.com/VanSail-Opensource/X-Node/internal/kernel/xray"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func assetKey(c protocol.Config, p geodata.Policy) string {
	raw, _ := json.Marshal([]any{p, c.AssetHashes})
	return string(raw)
}

// prepareNative is shared by activation and read-only command validation.
// The caller owns nativeMu; managed paths do not rely on ambient asset settings.
func (a *Agent) prepareNative(ctx, lifetime context.Context, c protocol.Config, p geodata.Policy) (protocol.Config, string, error) {
	return a.prepareResolved(ctx, c, p, func(c protocol.Config) (protocol.Config, error) { return a.Certificates.Prepare(lifetime, c) })
}
func (a *Agent) validateNative(ctx context.Context, c protocol.Config, p geodata.Policy) error {
	return cert.ValidateProfiles(ctx, c, func(resolved protocol.Config) error {
		_, _, err := a.prepareResolved(ctx, c, p, func(protocol.Config) (protocol.Config, error) { return resolved, nil })
		return err
	})
}
func (a *Agent) prepareResolved(ctx context.Context, c protocol.Config, p geodata.Policy, prepare func(protocol.Config) (protocol.Config, error)) (protocol.Config, string, error) {
	if policy := c.Firewall.SourceGeoIP; policy != nil && policy.Reference {
		ready, err := a.Guard.SyncGeoIP(ctx, protocol.GeoIPChunk{Generation: policy.Generation, Probe: true})
		if err != nil {
			return c, "", err
		}
		if !ready {
			return c, "", errors.New("country range generation is not staged")
		}
	}
	target := a.geoCandidate
	usingCandidate := target != "" && a.geoCandidateKey == assetKey(c, p)
	var err error
	if !usingCandidate {
		target, err = a.ensureAssets(ctx, c, p, false)
		if err != nil {
			return c, "", fmt.Errorf("prepare domain assets: %w", err)
		}
	}
	resolved, err := prepare(c)
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
		if usingCandidate || len(p.Assets) == 0 || !strings.Contains(err.Error(), "geosite") {
			return c, "", err
		}
		// A newly selected category can be absent from an otherwise valid cached
		// generation. Refresh once; failed candidates are retained for paced retry.
		target, err = a.ensureAssets(ctx, c, p, true)
		if err != nil {
			return c, "", fmt.Errorf("refresh domain assets: %w", err)
		}
		a.geoCandidate, a.geoCandidateKey = target, assetKey(c, p)
		env["XRAY_LOCATION_ASSET"] = target
		resolved.Xray, err = json.Marshal(native)
		if err != nil {
			return c, "", err
		}
		if _, err = xray.Prepare(resolved); err != nil {
			return c, "", err
		}
	}
	if len(p.Assets) > 0 {
		a.geoCandidate, a.geoCandidateKey = target, assetKey(c, p)
	}
	return resolved, target, nil
}
