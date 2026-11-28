package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (a *Agent) failStorage(err error) {
	a.Registry.Pause(true)
	a.Runtime.Stop()
	reason := a.Logs.Redact(err.Error())
	nlog.Core().Error("durable state unavailable; proxy admission stopped", "error", reason)
	a.Client.Send(protocol.New("agent.error", "", 0, map[string]string{"error": "durable state unavailable: " + reason}), true)
}
func (a *Agent) registerSecrets(configs ...protocol.Config) {
	values := []string{a.Client.Token}
	credential := func(raw json.RawMessage) {
		var fields map[string]any
		_ = json.Unmarshal(raw, &fields)
		for _, value := range fields {
			if secret, ok := value.(string); ok {
				values = append(values, secret)
			}
		}
	}
	secretValue := func(value any) {
		if secret, ok := value.(string); ok {
			values = append(values, secret)
		}
	}
	var walk func(any)
	walk = func(v any) {
		switch node := v.(type) {
		case map[string]any:
			for key, value := range node {
				switch strings.ToLower(key) {
				case "id", "password", "auth", "token", "privatekey", "key", "pass", "shortid", "mldsa65seed", "mldsa65verify":
					secretValue(value)
				case "shortids":
					if ids, ok := value.([]any); ok {
						for _, id := range ids {
							secretValue(id)
						}
					}
				}
				walk(value)
			}
		case []any:
			for _, item := range node {
				walk(item)
			}
		}
	}
	for _, c := range configs {
		for _, u := range c.Users {
			values = append(values, u.UUID)
			for _, raw := range u.Credentials {
				credential(raw)
			}
			for _, binding := range u.TransitCredentials {
				credential(binding.Credential)
			}
		}
		for _, p := range c.Providers {
			for _, secret := range p.Credentials {
				values = append(values, secret)
			}
		}
		for _, p := range c.Certificates {
			values = append(values, p.Config.KeyContent)
			for _, secret := range p.Config.DNSEnv {
				values = append(values, secret)
			}
		}
		var native any
		_ = json.Unmarshal(c.Xray, &native)
		walk(native)
	}
	a.Logs.SetSecrets(values...)
}
func (a *Agent) queue(ctx context.Context, job applyJob) {
	a.materialPending = a.materialPending || job.RecheckMaterial
	job.RecheckMaterial = a.materialPending
	finishReload(a.reloadDone, errActivationSuperseded)
	a.reloadDone = job.Done
	if a.cancelApply != nil {
		a.cancelApply()
	}
	a.generation++
	job.Generation = a.generation
	child, cancel := context.WithCancel(ctx)
	a.cancelApply = cancel
	job.Context = child
	select {
	case a.apply <- job:
	default:
		select {
		case <-a.apply:
		default:
		}
		a.apply <- job
	}
	a.applying.Store(true)
}
func (a *Agent) applyLoop(ctx context.Context, recoverOnStart bool) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-a.apply:
			err := a.activate(ctx, job)
			if recoverOnStart && err != nil && !a.Runtime.Ready() {
				if fallbackErr := a.restoreAcceptedRuntime(ctx, job); fallbackErr != nil {
					err = errors.Join(err, fmt.Errorf("restore last accepted runtime: %w", fallbackErr))
				}
			}
			// Only cold startup needs this fallback. A running instance has
			// its own last-known-good native snapshot for a failed cutover.
			recoverOnStart = recoverOnStart && !a.Runtime.Ready()
			select {
			case a.applied <- applied{Job: job, Error: err}:
			case <-ctx.Done():
				return
			}
		}
	}
}
