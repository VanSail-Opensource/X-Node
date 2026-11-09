package cert

import (
	"context"
	"errors"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/kernel"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Candidate never enters transport or job journals; material stays node-local.
type Candidate struct {
	ProfileID   string
	Key         string
	Fingerprint string
	Expires     time.Time
	Material    kernel.TLSCert `json:"-"`
}

func (p *Pool) Acquire(ctx, lifetime context.Context, c protocol.Config, args protocol.CertificateRunArgs, commandID string, eligible ...func() bool) (Candidate, error) {
	key, ok := ProfileKey(c, args.ProfileID)
	candidate := Candidate{ProfileID: args.ProfileID, Key: key}
	if !ok {
		return candidate, errors.New("CERTIFICATE_INPUT_INVALID")
	}
	spec := c.Certificates[args.ProfileID]
	cfg, _ := profileSettings(c, spec)
	mode := NewManager(cfg).resolveMode()
	if mode != "http" && mode != "dns" {
		return candidate, errors.New("CERTIFICATE_NOT_ACME")
	}
	if err := p.prepareMu.LockContext(ctx); err != nil {
		return candidate, err
	}
	entry, release := p.lease(c, spec)
	p.prepareMu.Unlock()
	defer release()
	if err := lockProfile(ctx, entry); err != nil {
		return candidate, err
	}
	defer unlockProfile(entry)
	if err := ctx.Err(); err != nil {
		return candidate, err
	}
	if len(eligible) > 0 && !eligible[0]() {
		return candidate, errors.New("CERTIFICATE_SUPERSEDED")
	}
	phase := "issuing"
	if args.Action == "renew" {
		phase = "renewing"
	}
	p.profilePhase(key, commandID, phase, "")
	started := time.Now()
	acquire := p.acquireFn
	if acquire == nil {
		acquire = func(ctx, lifetime context.Context, manager *Manager, action string) error {
			return manager.acquire(ctx, lifetime, action)
		}
	}
	if err := acquire(ctx, lifetime, entry.manager, args.Action); err != nil {
		code := "CERTIFICATE_ISSUE_FAILED"
		if args.Action == "renew" {
			code = "CERTIFICATE_RENEW_FAILED"
		}
		p.profilePhase(key, commandID, "failed", code)
		return candidate, errors.New(code)
	}
	entry.elapsed.Store(time.Since(started).Milliseconds())
	material := entry.manager.TLSCert()
	metadata, err := describeMaterial(material.CertPEM)
	if err != nil {
		return candidate, errors.New("CERTIFICATE_MATERIAL_INVALID")
	}
	candidate.Material, candidate.Fingerprint, candidate.Expires = material, metadata.Fingerprint, metadata.Expires
	p.acquired(key, metadata, entry.elapsed.Load())
	p.profilePhase(key, commandID, "applying", "")
	return candidate, nil
}
