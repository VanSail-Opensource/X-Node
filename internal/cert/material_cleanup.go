package cert

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"os"
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/config"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func profileSettings(c protocol.Config, spec protocol.Certificate) (config.CertConfig, string) {
	cfg := spec.Config
	if spec.Provider != "" {
		provider := c.Providers[spec.Provider]
		cfg.DNSProvider = provider.Type
		cfg.DNSEnv = protocol.Clone(provider.Credentials)
	}
	raw, _ := json.Marshal(cfg)
	hash := sha256.Sum256(raw)
	return cfg, hex.EncodeToString(hash[:])
}

// RetainStored seeds rollback protection from the last accepted configuration,
// including when a newer desired configuration is retried after a restart.
func (p *Pool) RetainStored(c protocol.Config) {
	p.prepareMu.Lock()
	defer p.prepareMu.Unlock()
	material, acme := map[string]bool{}, map[string]bool{}
	p.mu.Lock()
	if p.currentMaterial == nil {
		p.currentMaterial = map[string]bool{}
	}
	if p.currentACME == nil {
		p.currentACME = map[string]bool{}
	}
	p.mu.Unlock()
	for _, spec := range c.Certificates {
		cfg, _ := profileSettings(c, spec)
		hash := sha256.Sum256([]byte(cfg.CertMode + ":" + cfg.Domain + ":" + cfg.Email))
		name := hex.EncodeToString(hash[:])
		acme[name] = true
		dir := filepath.Join(p.dir, "acme", name)
		certificate, err := readCertificateFile(filepath.Join(dir, "cert.pem"))
		if err != nil {
			continue
		}
		key, err := readCertificateFile(filepath.Join(dir, "key.pem"))
		if err != nil {
			continue
		}
		pair := append(certificate, key...)
		materialHash := sha256.Sum256(pair)
		material[hex.EncodeToString(materialHash[:])] = true
	}
	p.mu.Lock()
	maps.Copy(p.currentMaterial, material)
	maps.Copy(p.currentACME, acme)
	p.mu.Unlock()
}

func (p *Pool) cleanupMaterial(used map[string]bool) {
	current := map[string]bool{}
	acme := map[string]bool{}
	p.mu.Lock()
	maps.Copy(current, p.runtimeMaterial)
	for key := range used {
		entry := p.profiles[key]
		if entry == nil {
			continue
		}
		material := entry.manager.TLSCert()
		pair := append(append([]byte(nil), material.CertPEM...), material.KeyPEM...)
		hash := sha256.Sum256(pair)
		current[hex.EncodeToString(hash[:])] = true
		if entry.manager.cfg.CertDir != "" {
			acme[filepath.Base(entry.manager.cfg.CertDir)] = true
		}
	}
	if !maps.Equal(current, p.currentMaterial) {
		p.previousMaterial, p.currentMaterial = p.currentMaterial, current
	}
	if !maps.Equal(acme, p.currentACME) {
		p.previousACME, p.currentACME = p.currentACME, acme
	}
	materialCurrent, materialPrevious := maps.Clone(p.currentMaterial), maps.Clone(p.previousMaterial)
	acmeCurrent, acmePrevious := maps.Clone(p.currentACME), maps.Clone(p.previousACME)
	for path := range p.prepared {
		name := filepath.Base(filepath.Dir(path))
		if !materialCurrent[name] && !materialPrevious[name] {
			delete(p.prepared, path)
		}
	}
	p.mu.Unlock()
	for _, item := range []struct {
		name              string
		current, previous map[string]bool
	}{{"material", materialCurrent, materialPrevious}, {"acme", acmeCurrent, acmePrevious}} {
		if err := pruneCertificateDirectories(filepath.Join(p.dir, item.name), item.current, item.previous); err != nil {
			slog.Warn("certificate cleanup pending", "error_code", "CERTIFICATE_CLEANUP_PENDING")
		}
	}
}

func pruneCertificateDirectories(root string, current, previous map[string]bool) error {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	removed := 0
	for _, entry := range entries {
		if !entry.IsDir() || len(entry.Name()) != 64 || current[entry.Name()] || previous[entry.Name()] {
			continue
		}
		if _, err := hex.DecodeString(entry.Name()); err != nil {
			continue
		}
		target := filepath.Join(root, entry.Name())
		if filepath.Dir(target) != filepath.Clean(root) {
			return errors.New("invalid certificate cleanup scope")
		}
		if err := os.RemoveAll(target); err != nil {
			return err
		}
		removed++
		if removed == 64 {
			break
		}
	}
	return nil
}
