package agent

import (
	"context"
	"errors"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/dns"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Scheduled and manual jobs share one serialized discovery/provider path.
func (a *Agent) runDDNS(ctx context.Context, configuration protocol.Config, job protocol.DDNSJob) (dns.Result, error) {
	a.dnsMu.Lock()
	defer a.dnsMu.Unlock()
	child, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if job.Generation != "" && a.ddnsJournal == nil {
		return dns.Result{}, errors.New("DDNS journal unavailable")
	}
	var provider any
	if job.Provider != protocol.BuiltinDDNSProvider {
		var err error
		provider, err = dns.Provider(configuration.Providers[job.Provider])
		if err != nil {
			return dns.Result{}, err
		}
	}
	result, err := dns.DDNS(child, job, provider, nil)
	if err == nil && job.Generation != "" {
		err = a.ddnsJournal.Record(job, result.IPv4, result.IPv6, result.Updated, configuration.DDNS)
	}
	return result, err
}
