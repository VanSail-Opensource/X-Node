package agent

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"strings"
)

func (a *Agent) failStorage(err error) {
	a.Registry.Pause(true)
	a.Runtime.Stop()
	nlog.Core().Error("durable state unavailable; proxy admission stopped")
	a.Client.Send(protocol.New("agent.error", "", 0, map[string]string{"error": "durable state unavailable"}), true)
}
func (a *Agent) registerSecrets(c protocol.Config) {
	values := []string{a.Client.Token}
	for _, u := range c.Users {
		values = append(values, u.UUID)
		for _, raw := range u.Credentials {
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			for _, v := range m {
				if secret, ok := v.(string); ok {
					values = append(values, secret)
				}
			}
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
	var walk func(any)
	walk = func(v any) {
		switch node := v.(type) {
		case map[string]any:
			for key, value := range node {
				switch strings.ToLower(key) {
				case "id", "password", "auth", "token", "privatekey", "key", "pass":
					if secret, ok := value.(string); ok {
						values = append(values, secret)
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
	walk(native)
	a.Logs.SetSecrets(values...)
}
func (a *Agent) queue(ctx context.Context, job applyJob) {
	finishReload(a.reloadDone, errors.New("configuration superseded"))
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
func (a *Agent) applyLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-a.apply:
			err := a.activate(ctx, job)
			select {
			case a.applied <- applied{Job: job, Error: err}:
			case <-ctx.Done():
				return
			}
		}
	}
}
