package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type materialStatus struct {
	Fingerprint        string
	NotBefore, Expires time.Time
	SANs               []string
	Issuer             string
}

func describeMaterial(raw []byte) (materialStatus, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return materialStatus{}, errors.New("invalid certificate material")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return materialStatus{}, errors.New("invalid certificate material")
	}
	hash := sha256.Sum256(leaf.Raw)
	sans := slices.Clone(leaf.DNSNames[:min(len(leaf.DNSNames), 128)])
	for _, ip := range leaf.IPAddresses {
		if len(sans) == 128 {
			break
		}
		sans = append(sans, ip.String())
	}
	for i := range sans {
		sans[i] = publicCertificateText(sans[i], 253)
	}
	return materialStatus{hex.EncodeToString(hash[:]), leaf.NotBefore, leaf.NotAfter, sans, publicCertificateText(leaf.Issuer.String(), 512)}, nil
}

func publicCertificateText(value string, limit int) string {
	if len(value) > limit {
		value = value[:limit]
	}
	return strings.ToValidUTF8(value, "")
}

// Declare is actor-safe: publish all desired profiles, including failed targets.
func (p *Pool) Declare(c protocol.Config, revision uint64) {
	p.statusMu.Lock()
	defer p.statusMu.Unlock()
	desired := map[string]string{}
	ids := make([]string, 0, len(c.Certificates))
	for id := range c.Certificates {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids[:min(len(ids), protocol.MaxCertificateProfiles)] {
		spec := c.Certificates[id]
		cfg, key := profileSettings(c, spec)
		desired[id] = key
		status := p.statuses[id]
		if p.desired[id] != key {
			status.Phase = "idle"
			status.ErrorCode = ""
			status.AcquiredFingerprint = ""
			status.CommandID = ""
		}
		status.Domain, status.Mode, status.Revision = publicCertificateText(cfg.Domain, 253), NewManager(cfg).resolveMode(), revision
		p.statuses[id] = status
	}
	for id, status := range p.statuses {
		if _, ok := desired[id]; !ok && !status.Active {
			delete(p.statuses, id)
		}
	}
	p.desired = desired
}

func (p *Pool) Status() map[string]ProfileStatus {
	p.statusMu.Lock()
	defer p.statusMu.Unlock()
	out := make(map[string]ProfileStatus, len(p.statuses))
	for id, status := range p.statuses {
		status.SANs = slices.Clone(status.SANs)
		status.Expiring = !status.Expires.IsZero() && time.Until(status.Expires) < 30*24*time.Hour
		out[id] = status
	}
	return out
}

func (p *Pool) profilePhase(key, command, phase, code string) {
	p.statusMu.Lock()
	defer p.statusMu.Unlock()
	for id, wanted := range p.desired {
		if wanted != key {
			continue
		}
		status := p.statuses[id]
		status.Phase, status.ErrorCode = phase, code
		if command != "" {
			status.CommandID = command
		}
		if phase == "issuing" || phase == "renewing" {
			status.LastAttempt = time.Now().UTC()
		}
		p.statuses[id] = status
	}
}

func (p *Pool) acquired(key string, material materialStatus, elapsed ...int64) {
	p.statusMu.Lock()
	defer p.statusMu.Unlock()
	for id, wanted := range p.desired {
		if wanted != key {
			continue
		}
		status := p.statuses[id]
		status.AcquiredFingerprint = material.Fingerprint
		if len(elapsed) > 0 {
			status.ObtainMillis = elapsed[0]
		}
		p.statuses[id] = status
	}
}

func (p *Pool) profileEvent(key string, manager *Manager, event string, data map[string]any) {
	p.mu.Lock()
	entry := p.profiles[key]
	current := entry != nil && entry.manager == manager
	p.mu.Unlock()
	if !current {
		return
	}
	switch event {
	case "cert_obtaining":
		phase := "issuing"
		if renewal, _ := data["renewal"].(bool); renewal {
			phase = "renewing"
		}
		p.profilePhase(key, "", phase, "")
	case "cert_obtained":
		if material, err := describeMaterial(manager.TLSCert().CertPEM); err == nil {
			p.acquired(key, material)
		}
		p.profilePhase(key, "", "applying", "")
	case "cert_failed":
		p.profilePhase(key, "", "failed", "CERTIFICATE_ACME_FAILED")
	}
}
