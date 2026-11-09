package cert

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"slices"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// RetainRuntime records exact prepared material immediately after runtime success,
// even if later firewall/state acceptance fails. Commit is a separate boundary.
func (p *Pool) RetainRuntime(c protocol.Config, resolved ...protocol.Config) {
	metadata := map[string]materialStatus{}
	keys := map[string]string{}
	p.mu.Lock()
	p.runtimeKeys, p.runtimeMaterial = map[string]bool{}, map[string]bool{}
	for id, spec := range c.Certificates {
		_, key := profileSettings(c, spec)
		keys[id] = key
		p.runtimeKeys[key] = true
		if len(resolved) > 0 {
			file := resolved[0].Certificates[id].Config.CertFile
			p.runtimeMaterial[filepath.Base(filepath.Dir(file))] = true
			if value, ok := p.prepared[file]; ok {
				metadata[id] = value
			}
		} else if entry := p.profiles[key]; entry != nil {
			material := entry.manager.TLSCert()
			pair := append(append([]byte(nil), material.CertPEM...), material.KeyPEM...)
			hash := sha256.Sum256(pair)
			p.runtimeMaterial[hex.EncodeToString(hash[:])] = true
			if value, err := describeMaterial(material.CertPEM); err == nil {
				metadata[id] = value
			}
		}
	}
	p.mu.Unlock()
	p.statusMu.Lock()
	defer p.statusMu.Unlock()
	for id, status := range p.statuses {
		if _, ok := keys[id]; !ok {
			status.Active = false
			status.Fingerprint = ""
			status.Expires = time.Time{}
			status.NotBefore = time.Time{}
			status.SANs = nil
			status.Issuer = ""
			p.statuses[id] = status
		}
	}
	p.servingKeys = keys
	for id, material := range metadata {
		status := p.statuses[id]
		status.Active = true
		status.Fingerprint = material.Fingerprint
		status.Expires, status.NotBefore, status.Issuer = material.Expires, material.NotBefore, material.Issuer
		status.SANs = slices.Clone(material.SANs)
		if status.Domain == "" {
			status.Domain = c.Certificates[id].Config.Domain
		}
		if status.Mode == "" {
			status.Mode = c.Certificates[id].Config.CertMode
		}
		if wanted := p.desired[id]; wanted == "" || wanted == keys[id] {
			status.Phase, status.ErrorCode = "idle", ""
		}
		status.LastSuccess = time.Now().UTC()
		p.statuses[id] = status
	}
}

func (p *Pool) ServingMatches(candidate Candidate) bool {
	p.statusMu.Lock()
	defer p.statusMu.Unlock()
	status := p.statuses[candidate.ProfileID]
	return status.Active && p.servingKeys[candidate.ProfileID] == candidate.Key && status.Fingerprint == candidate.Fingerprint
}

func (p *Pool) Result(candidate Candidate, action string, ready bool) protocol.CertificateRunResult {
	p.statusMu.Lock()
	status := p.statuses[candidate.ProfileID]
	key := p.servingKeys[candidate.ProfileID]
	p.statusMu.Unlock()
	return protocol.CertificateRunResult{ProfileID: candidate.ProfileID, Action: action, Fingerprint: status.Fingerprint, Expires: status.Expires, Applied: status.Active && key == candidate.Key && status.Fingerprint == candidate.Fingerprint, Ready: ready}
}

func (p *Pool) Failed(candidate Candidate, code string) {
	p.profilePhase(candidate.Key, "", "failed", code)
}

func (p *Pool) Completed(candidate Candidate) { p.profilePhase(candidate.Key, "", "idle", "") }
