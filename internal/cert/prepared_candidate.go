package cert

import "github.com/VanSail-Opensource/X-Node/internal/protocol"

func (p *Pool) PreparedMatches(candidate Candidate, resolved protocol.Config) bool {
	file := resolved.Certificates[candidate.ProfileID].Config.CertFile
	p.mu.Lock()
	metadata, ok := p.prepared[file]
	p.mu.Unlock()
	return ok && metadata.Fingerprint == candidate.Fingerprint
}
