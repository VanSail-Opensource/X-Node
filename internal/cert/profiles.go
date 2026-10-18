package cert

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"path/filepath"
	"sync"
	"time"
)

type ProfileStatus struct {
	Domain       string    `json:"domain"`
	Expires      time.Time `json:"expires"`
	Expiring     bool      `json:"expiring"`
	ObtainMillis int64     `json:"obtain_millis"`
}
type profile struct {
	manager *Manager
	elapsed int64
}
type Pool struct {
	mu               sync.Mutex
	dir              string
	profiles         map[string]*profile
	active           map[string]string
	currentMaterial  map[string]bool
	currentACME      map[string]bool
	previousMaterial map[string]bool
	previousACME     map[string]bool
}

func NewPool(dir string) *Pool {
	return &Pool{dir: dir, profiles: map[string]*profile{}, active: map[string]string{}}
}
func (p *Pool) Prepare(ctx context.Context, c protocol.Config) (protocol.Config, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := protocol.Clone(c)
	if len(c.Certificates) > 64 {
		return out, errors.New("too many certificate profiles")
	}
	prepared := map[string]bool{}
	for id, spec := range c.Certificates {
		cfg, key := profileSettings(c, spec)
		entry := p.profiles[key]
		fresh := entry == nil
		if entry == nil {
			storageHash := sha256.Sum256([]byte(cfg.CertMode + ":" + cfg.Domain + ":" + cfg.Email))
			cfg.CertDir = filepath.Join(p.dir, "acme", hex.EncodeToString(storageHash[:]))
			if cfg.CertMode == "file" || cfg.CertMode == "content" {
				cfg.CertDir = ""
			}
			manager := NewManager(cfg)
			start := time.Now()
			if err := manager.Start(ctx); err != nil {
				manager.Stop()
				return out, errors.New("certificate profile preparation failed")
			}
			entry = &profile{manager: manager, elapsed: time.Since(start).Milliseconds()}
			p.profiles[key] = entry
		}
		if cfg.CertMode == "file" && !prepared[key] && !fresh {
			if err := entry.manager.startFile(); err != nil {
				return out, err
			}
		}
		prepared[key] = true
		material := entry.manager.TLSCert()
		if len(material.CertPEM) == 0 || len(material.KeyPEM) == 0 {
			return out, errors.New("certificate profile has no TLS material")
		}
		pair := append(append([]byte(nil), material.CertPEM...), material.KeyPEM...)
		hash := sha256.Sum256(pair)
		dir := filepath.Join(p.dir, "material", hex.EncodeToString(hash[:]))
		certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
		if err := state.AtomicWrite(certFile, material.CertPEM, 0600); err != nil {
			return out, err
		}
		if err := state.AtomicWrite(keyFile, material.KeyPEM, 0600); err != nil {
			return out, err
		}
		spec.Config.CertFile = certFile
		spec.Config.KeyFile = keyFile
		out.Certificates[id] = spec
	}
	return out, nil
}
func (p *Pool) Commit(c protocol.Config) {
	p.mu.Lock()
	defer p.mu.Unlock()
	used := map[string]bool{}
	active := map[string]string{}
	for id, spec := range c.Certificates {
		_, key := profileSettings(c, spec)
		used[key] = true
		active[id] = key
	}
	p.active = active
	for key, entry := range p.profiles {
		if !used[key] {
			entry.manager.Stop()
			delete(p.profiles, key)
		}
	}
	p.cleanupMaterial(used)
}
func (p *Pool) Renewed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	renewed := false
	for _, e := range p.profiles {
		renewed = e.manager.CertRenewed() || renewed
	}
	return renewed
}
func (p *Pool) Status() map[string]ProfileStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]ProfileStatus{}
	for id, key := range p.active {
		e := p.profiles[key]
		if e == nil {
			continue
		}
		b, _ := pem.Decode(e.manager.TLSCert().CertPEM)
		if b == nil {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err == nil {
			out[id] = ProfileStatus{Domain: c.Subject.CommonName, Expires: c.NotAfter, Expiring: time.Until(c.NotAfter) < 30*24*time.Hour, ObtainMillis: e.elapsed}
		}
	}
	return out
}
func (p *Pool) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.profiles {
		e.manager.Stop()
	}
	p.profiles = map[string]*profile{}
}
