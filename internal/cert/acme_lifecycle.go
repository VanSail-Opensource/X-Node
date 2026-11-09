package cert

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// Public PreChecker extension disables prompts while preserving optional email.
type headlessIssuer struct{ *certmagic.ACMEIssuer }

func (i headlessIssuer) PreCheck(ctx context.Context, names []string, _ bool) error {
	return i.ACMEIssuer.PreCheck(ctx, names, false)
}

func (m *Manager) acquire(ctx, lifetime context.Context, action string) error {
	if mode := m.resolveMode(); mode != "http" && mode != "dns" {
		return fmt.Errorf("CERTIFICATE_NOT_ACME")
	}
	var solver *certmagic.DNS01Solver
	if m.resolveMode() == "dns" {
		var err error
		solver, err = m.buildDNSSolver()
		if err != nil {
			return err
		}
	}
	return m.acquireACME(ctx, lifetime, solver, action == "renew")
}

func (m *Manager) acquireACME(ctx, lifetime context.Context, solver *certmagic.DNS01Solver, renew bool) (result error) {
	if m.acmeStarted && !renew {
		if material, err := describeMaterial(m.TLSCert().CertPEM); err == nil && material.Expires.After(time.Now()) {
			return nil
		}
		renew = true
	}
	if m.cfg.Domain == "" {
		return fmt.Errorf("certificate domain is required")
	}
	if err := os.MkdirAll(m.cfg.CertDir, 0700); err != nil {
		return err
	}
	storage := &certmagic.FileStorage{Path: m.cfg.CertDir}
	initialized := !m.acmeStarted
	if initialized {
		var magic *certmagic.Config
		cache := certmagic.NewCache(certmagic.CacheOptions{Logger: zap.NewNop(), GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil }})
		magic = certmagic.New(cache, certmagic.Config{Logger: zap.NewNop(), Storage: storage, OnEvent: func(eventCtx context.Context, event string, data map[string]any) error {
			if event == "cert_obtained" {
				if issuer, _ := data["issuer"].(string); issuer != "" {
					if err := m.loadPEMFromStorage(eventCtx, storage, issuer, m.cfg.Domain); err != nil {
						if m.onEvent != nil {
							m.onEvent("cert_failed", nil)
						}
						return nil
					}
					m.renewed.Store(true)
				}
			}
			if m.onEvent != nil {
				m.onEvent(event, data)
			}
			return nil
		}})
		issuer := certmagic.ACMEIssuer{CA: certmagic.LetsEncryptProductionCA, Email: m.cfg.Email, Agreed: true}
		if solver != nil {
			issuer.DNS01Solver = solver
			issuer.DisableHTTPChallenge = true
		} else {
			issuer.AltHTTPPort = m.cfg.HTTPPort
			if issuer.AltHTTPPort == 0 {
				issuer.AltHTTPPort = 80
			}
		}
		issuer.DisableTLSALPNChallenge = true
		magic.Issuers = []certmagic.Issuer{headlessIssuer{certmagic.NewACMEIssuer(magic, issuer)}}
		m.magic, m.cache = magic, cache
		defer func() {
			if result != nil {
				cache.Stop()
				m.magic = nil
				m.cache = nil
			}
		}()
	}
	startup := time.Duration(m.cfg.StartupTimeoutSeconds) * time.Second
	if startup <= 0 {
		startup = 2 * time.Minute
	}
	startup = min(startup, 5*time.Minute)
	attempt, cancel := context.WithTimeout(ctx, startup)
	defer cancel()
	if renew {
		result = m.magic.RenewCertSync(attempt, m.cfg.Domain, true)
	} else {
		result = m.magic.ObtainCertSync(attempt, m.cfg.Domain)
	}
	if result != nil {
		return result
	}
	cached, err := m.magic.CacheManagedCertificate(attempt, m.cfg.Domain)
	if err != nil {
		return err
	}
	if !renew && !cached.Leaf.NotAfter.After(time.Now()) {
		if result = m.magic.RenewCertSync(attempt, m.cfg.Domain, true); result != nil {
			return result
		}
		if _, result = m.magic.CacheManagedCertificate(attempt, m.cfg.Domain); result != nil {
			return result
		}
	}
	issuerKey := m.magic.Issuers[0].IssuerKey()
	if result = m.loadPEMFromStorage(attempt, storage, issuerKey, m.cfg.Domain); result != nil {
		return result
	}
	if initialized {
		background, stop := context.WithCancel(lifetime)
		if result = m.magic.ManageAsync(background, []string{m.cfg.Domain}); result != nil {
			stop()
			return result
		}
		m.acmeCancel = stop
		m.acmeFingerprint = acmeFingerprint(m.cfg)
		m.acmeStarted = true
	}
	if renew {
		m.renewed.Store(true)
	}
	return nil
}
