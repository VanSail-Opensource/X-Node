package cert

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type operationMutex struct{ gate chan struct{} }

func (m operationMutex) Lock()   { m.gate <- struct{}{} }
func (m operationMutex) Unlock() { <-m.gate }
func (m operationMutex) LockContext(ctx context.Context) error {
	select {
	case m.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Caller owns prepareMu so a new cache directory cannot race pruning.
func (p *Pool) lease(c protocol.Config, spec protocol.Certificate) (*profile, func()) {
	cfg, key := profileSettings(c, spec)
	p.mu.Lock()
	entry := p.profiles[key]
	if entry == nil {
		hash := sha256.Sum256([]byte(cfg.CertMode + ":" + cfg.Domain + ":" + cfg.Email))
		cfg.CertDir = filepath.Join(p.dir, "acme", hex.EncodeToString(hash[:]))
		if cfg.CertMode == "file" || cfg.CertMode == "content" {
			cfg.CertDir = ""
		}
		manager := NewManager(cfg)
		entry = &profile{manager: manager, gate: make(chan struct{}, 1)}
		manager.onEvent = func(event string, data map[string]any) { p.profileEvent(key, manager, event, data) }
		p.profiles[key] = entry
	}
	entry.refs++
	p.mu.Unlock()
	return entry, func() { p.mu.Lock(); entry.refs--; p.mu.Unlock() }
}

func lockProfile(ctx context.Context, entry *profile) error {
	select {
	case entry.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func unlockProfile(entry *profile) { <-entry.gate }

func initialPhase(manager *Manager) string {
	if manager.HasCert() {
		return "applying"
	}
	if mode := manager.resolveMode(); mode == "http" || mode == "dns" {
		return "issuing"
	}
	return "applying"
}

func (p *Pool) retireProfiles(keep map[string]bool) {
	p.mu.Lock()
	var retired []*profile
	for key, entry := range p.profiles {
		if !keep[key] && entry.refs == 0 {
			retired = append(retired, entry)
			delete(p.profiles, key)
		}
	}
	p.mu.Unlock()
	for _, entry := range retired {
		entry.manager.Stop()
	}
}

// ProfileKey binds provider credentials and all native profile settings without
// exposing that private digest through status or command results.
func ProfileKey(c protocol.Config, id string) (string, bool) {
	spec, ok := c.Certificates[id]
	if !ok {
		return "", false
	}
	_, key := profileSettings(c, spec)
	return key, true
}

func IsACMEProfile(c protocol.Config, id string) bool {
	spec, ok := c.Certificates[id]
	if !ok {
		return false
	}
	cfg, _ := profileSettings(c, spec)
	mode := NewManager(cfg).resolveMode()
	return mode == "http" || mode == "dns"
}
