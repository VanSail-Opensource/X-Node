package update

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"os"
	"runtime"
	"time"
)

func (m *Manager) Install(ctx context.Context, id, version string, progress func(any)) (Release, error) {
	result, e := m.Check(ctx, version)
	if e != nil {
		return result, e
	}
	if !result.Available {
		return result, nil
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return result, errors.New("binary upgrades require Linux amd64/arm64")
	}
	if e = host.CheckRequirements(); e != nil {
		return result, e
	}
	if _, e = PublicKey(); e != nil {
		return result, e
	}
	if e = os.MkdirAll(m.Dir, 0700); e != nil {
		return result, e
	}
	unlock, e := m.lock(ctx)
	if e != nil {
		return result, e
	}
	defer unlock()
	if t, e := m.read(); e == nil && t.Status == "pending" {
		return result, errors.New("another upgrade is pending")
	}
	base := "https://github.com/" + Repository + "/releases/download/" + result.Version + "/"
	progress(map[string]string{"stage": "verify_manifest"})
	manifest, e := m.fetch(ctx, base+"SHA256SUMS", 1<<20)
	if e != nil {
		return result, e
	}
	signature, e := m.fetch(ctx, base+"SHA256SUMS.minisig", 4096)
	if e != nil {
		return result, e
	}
	hashes, e := Verify(manifest, signature, result.Version)
	if e != nil {
		return result, e
	}
	targets := []string{m.NodePath, m.CLIPath}
	names := []string{"x-node-linux-" + runtime.GOARCH, "xnodectl-linux-" + runtime.GOARCH}
	for i, name := range names {
		hash := hashes[name]
		if hash == "" {
			return result, errors.New("signed manifest lacks target binary")
		}
		progress(map[string]string{"stage": "download", "artifact": name})
		b, e := m.fetch(ctx, base+name, 256<<20)
		if e != nil {
			return result, e
		}
		staged := targets[i] + ".new"
		if e = state.AtomicWrite(staged, b, 0600); e != nil {
			return result, e
		}
		if e = VerifyFile(staged, hash); e != nil {
			return result, e
		}
		if e = os.Chmod(staged, 0755); e != nil {
			return result, e
		}
		out, e := m.Runner.Run(ctx, staged, "--version")
		if e != nil {
			return result, e
		}
		var info struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(out, &info) != nil || info.Version != result.Version {
			return result, errors.New("staged binary version differs")
		}
		if i == 0 {
			if e = m.checkCapabilities(out); e != nil {
				return result, e
			}
		}
	}
	for _, target := range targets {
		old, e := os.ReadFile(target)
		if e != nil {
			return result, e
		}
		if e = state.AtomicWrite(target+".old", old, 0755); e != nil {
			return result, e
		}
	}
	transaction := Transaction{ID: id, Version: result.Version, Previous: m.Current, Status: "pending", Deadline: time.Now().Add(45 * time.Second), Unit: "x-node-upgrade-rollback", NodePath: m.NodePath, CLIPath: m.CLIPath}
	if e = m.write(transaction); e != nil {
		return result, e
	}
	if _, e = m.Runner.Run(ctx, "systemd-run", "--unit="+transaction.Unit, "--on-active=45s", "--collect", m.CLIPath, "upgrade-rollback", "--state-dir", m.Dir); e != nil {
		transaction.Status = "failed"
		_ = m.write(transaction)
		return result, e
	}
	for _, target := range targets {
		if e = os.Rename(target+".new", target); e != nil {
			rollbackErr := m.restore(ctx, &transaction)
			unlock()
			if rollbackErr == nil {
				rollbackErr = m.restart(ctx)
			}
			return result, errors.Join(e, rollbackErr)
		}
	}
	unlock()
	progress(map[string]string{"stage": "restart"})
	if e = m.restart(ctx); e != nil {
		return result, errors.Join(e, m.Rollback(ctx))
	}
	return result, nil
}
