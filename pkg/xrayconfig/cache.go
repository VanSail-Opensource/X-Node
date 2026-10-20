package xrayconfig

import (
	"sync"

	"github.com/VanSail-Opensource/X-Node/internal/kernel/xray"
	"github.com/VanSail-Opensource/X-Node/pkg/protocol"
)

// Validator retains one successful immutable candidate. Keep one per owner/node
// context; it never starts listeners and never persists native documents.
type Validator struct {
	mu       sync.Mutex
	previous *xray.Prepared
	counts   BuildCounts
}

// BuildCounts reports actual upstream native section builder invocations.
type BuildCounts = xray.BuildCounts

func (v *Validator) Validate(config protocol.Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	next, err := xray.PrepareCached(config, v.previous)
	if err != nil {
		return err
	}
	v.previous = next
	v.counts.Native += next.Counts.Native
	v.counts.Inbounds += next.Counts.Inbounds
	v.counts.Outbounds += next.Counts.Outbounds
	v.counts.Routing += next.Counts.Routing
	return nil
}

func (v *Validator) Counts() BuildCounts {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.counts
}
