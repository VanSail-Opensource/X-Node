package cert

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/kernel"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

type ProfileStatus = protocol.CertificateStatus

type profile struct {
	manager *Manager
	gate    chan struct{}
	refs    int // protected by Pool.mu
	elapsed atomic.Int64
}

type Pool struct {
	mu                                sync.Mutex // Metadata only; never held across disk, network or manager shutdown.
	prepareMu                         operationMutex
	statusMu                          sync.Mutex
	dir                               string
	profiles                          map[string]*profile
	active                            map[string]string
	runtimeKeys                       map[string]bool
	runtimeMaterial                   map[string]bool
	currentMaterial, previousMaterial map[string]bool
	currentACME, previousACME         map[string]bool
	statuses                          map[string]ProfileStatus
	desired                           map[string]string
	servingKeys                       map[string]string
	prepared                          map[string]materialStatus
	acquireFn                         func(context.Context, context.Context, *Manager, string) error
}

func NewPool(dir string) *Pool {
	return &Pool{dir: dir, prepareMu: operationMutex{make(chan struct{}, 1)}, profiles: map[string]*profile{}, active: map[string]string{}, statuses: map[string]ProfileStatus{}, desired: map[string]string{}, servingKeys: map[string]string{}, prepared: map[string]materialStatus{}}
}

func (p *Pool) Prepare(ctx context.Context, c protocol.Config) (protocol.Config, error) {
	return p.PrepareContext(ctx, ctx, c, nil)
}

// PrepareContext stages immutable material while renewal managers outlive attempts.
// An explicit candidate pins all aliases of its profile to exactly those bytes.
func (p *Pool) PrepareContext(ctx, lifetime context.Context, c protocol.Config, candidate *Candidate) (protocol.Config, error) {
	if err := p.prepareMu.LockContext(ctx); err != nil {
		return protocol.Config{}, err
	}
	defer p.prepareMu.Unlock()
	out := protocol.Clone(c)
	if len(c.Certificates) > protocol.MaxCertificateProfiles {
		return out, errors.New("too many certificate profiles")
	}
	p.discardUnusedCandidates(c)
	prepared := map[string]kernel.TLSCert{}
	for id, spec := range c.Certificates {
		_, key := profileSettings(c, spec)
		entry, release := p.lease(c, spec)
		if err := lockProfile(ctx, entry); err != nil {
			release()
			return out, err
		}
		material := entry.manager.TLSCert()
		var err error
		if shared, ok := prepared[key]; ok {
			material = shared
		} else if candidate != nil && candidate.Key == key {
			material = candidate.Material
		} else {
			p.profilePhase(key, "", initialPhase(entry.manager), "")
			started := time.Now()
			err = entry.manager.StartContext(ctx, lifetime)
			entry.elapsed.Store(time.Since(started).Milliseconds())
			material = entry.manager.TLSCert()
		}
		unlockProfile(entry)
		release()
		if err != nil {
			p.profilePhase(key, "", "failed", "CERTIFICATE_PREPARATION_FAILED")
			return out, errors.New("CERTIFICATE_PREPARATION_FAILED")
		}
		if len(material.CertPEM) == 0 || len(material.KeyPEM) == 0 {
			return out, errors.New("certificate profile has no TLS material")
		}
		if err := validateKeyPair(material.CertPEM, material.KeyPEM); err != nil {
			return out, errors.New("CERTIFICATE_MATERIAL_INVALID")
		}
		prepared[key] = material
		pair := append(append([]byte(nil), material.CertPEM...), material.KeyPEM...)
		hash := sha256.Sum256(pair)
		dir := filepath.Join(p.dir, "material", hex.EncodeToString(hash[:]))
		certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
		if err = writeMaterial(certFile, material.CertPEM); err != nil {
			return out, err
		}
		if err = writeMaterial(keyFile, material.KeyPEM); err != nil {
			return out, err
		}
		metadata, err := describeMaterial(material.CertPEM)
		if err != nil {
			return out, err
		}
		p.mu.Lock()
		p.prepared[certFile] = metadata
		p.mu.Unlock()
		if candidate == nil || candidate.Key != key {
			p.acquired(key, metadata, entry.elapsed.Load())
		}
		spec.Config.CertFile, spec.Config.KeyFile = certFile, keyFile
		out.Certificates[id] = spec
	}
	return out, nil
}

func writeMaterial(path string, material []byte) error {
	if stored, err := os.ReadFile(path); err == nil && bytes.Equal(stored, material) {
		return nil
	}
	return state.AtomicWrite(path, material, 0600)
}

func (p *Pool) Commit(c protocol.Config) {
	p.prepareMu.Lock()
	defer p.prepareMu.Unlock()
	used, active := map[string]bool{}, map[string]string{}
	for id, spec := range c.Certificates {
		_, key := profileSettings(c, spec)
		used[key] = true
		active[id] = key
	}
	p.mu.Lock()
	p.active = active
	p.mu.Unlock()
	p.retireProfiles(used)
	p.cleanupMaterial(used)
}

func (p *Pool) Renewed() bool {
	p.mu.Lock()
	entries := make([]*profile, 0, len(p.profiles))
	for _, entry := range p.profiles {
		entries = append(entries, entry)
	}
	p.mu.Unlock()
	renewed := false
	for _, entry := range entries {
		renewed = entry.manager.CertRenewed() || renewed
	}
	return renewed
}

func (p *Pool) Stop() {
	p.prepareMu.Lock()
	defer p.prepareMu.Unlock()
	p.mu.Lock()
	entries := p.profiles
	p.profiles = map[string]*profile{}
	p.mu.Unlock()
	for _, entry := range entries {
		entry.gate <- struct{}{}
		entry.manager.Stop()
		unlockProfile(entry)
	}
}
