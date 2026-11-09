package cert

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"maps"
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// discardUnusedCandidates bounds failed preparations without rotating the
// serving/rollback material markers. Prepare owns prepareMu, never the status lock.
func (p *Pool) discardUnusedCandidates(c protocol.Config) {
	keep := map[string]bool{}
	p.mu.Lock()
	for _, key := range p.active {
		keep[key] = true
	}
	maps.Copy(keep, p.runtimeKeys)
	for key, entry := range p.profiles {
		if entry.refs > 0 {
			keep[key] = true
		}
	}
	p.mu.Unlock()
	for _, spec := range c.Certificates {
		_, key := profileSettings(c, spec)
		keep[key] = true
	}
	material, acme := map[string]bool{}, map[string]bool{}
	p.retireProfiles(keep)
	p.mu.Lock()
	maps.Copy(material, p.currentMaterial)
	maps.Copy(material, p.previousMaterial)
	maps.Copy(acme, p.currentACME)
	maps.Copy(acme, p.previousACME)
	maps.Copy(material, p.runtimeMaterial)
	for _, entry := range p.profiles {
		pair := entry.manager.TLSCert()
		raw := append(append([]byte(nil), pair.CertPEM...), pair.KeyPEM...)
		hash := sha256.Sum256(raw)
		material[hex.EncodeToString(hash[:])] = true
		if dir := entry.manager.cfg.CertDir; dir != "" {
			acme[filepath.Base(dir)] = true
		}
	}
	p.mu.Unlock()
	for _, item := range []struct {
		name string
		keep map[string]bool
	}{{"material", material}, {"acme", acme}} {
		if err := pruneCertificateDirectories(filepath.Join(p.dir, item.name), item.keep, nil); err != nil {
			slog.Warn("certificate candidate cleanup pending", "error_code", "CERTIFICATE_CLEANUP_PENDING")
		}
	}
}
