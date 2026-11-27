package xray

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"

	appdns "github.com/xtls/xray-core/app/dns"
	apppolicy "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
	"github.com/xtls/xray-core/features/policy"
	"google.golang.org/protobuf/proto"
)

var (
	dnsMessageType    = serial.GetMessageType(&appdns.Config{})
	policyMessageType = serial.GetMessageType(&apppolicy.Config{})
)

type dnsGeneration struct {
	client dns.Client
	cancel context.CancelFunc
	users  int
}

func newDNSGeneration(ctx context.Context, c *DNSConfig) (*dnsGeneration, error) {
	child, cancel := context.WithCancel(ctx)
	var client dns.Client
	if c.UseLocal {
		client = localdns.New()
	} else {
		compiled := new(appdns.Config)
		if err := proto.Unmarshal(c.NativeValue, compiled); err != nil {
			cancel()
			return nil, err
		}
		feature, err := appdns.New(child, compiled)
		if err != nil {
			cancel()
			return nil, err
		}
		client = feature
	}
	return &dnsGeneration{client: client, cancel: cancel}, nil
}

func (g *dnsGeneration) close() error {
	g.cancel()
	return g.client.Close()
}

// reloadableDNS is the feature reference held by the dispatcher, DNS
// outbounds and system dialer. A lookup pins only its own resolver generation.
type reloadableDNS struct {
	mu      sync.Mutex
	active  *dnsGeneration
	retired map[*dnsGeneration]struct{} // only resolvers with pending lookups
}

func (*reloadableDNS) Type() any      { return dns.ClientType() }
func (s *reloadableDNS) Start() error { return s.active.client.Start() }
func (s *reloadableDNS) Close() error {
	if old := s.replace(nil); old != nil {
		return old.close()
	}
	return nil
}

// replace returns an immediately closable generation if all its lookups have
// finished. Otherwise the final lookup takes ownership of closing it.
func (s *reloadableDNS) replace(next *dnsGeneration) *dnsGeneration {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.active
	s.active = next
	if old != nil && old.users > 0 {
		if s.retired == nil {
			s.retired = make(map[*dnsGeneration]struct{})
		}
		s.retired[old] = struct{}{}
		return nil
	}
	return old
}

func (s *reloadableDNS) LookupIP(domain string, option dns.IPOption) ([]xnet.IP, uint32, error) {
	s.mu.Lock()
	current := s.active
	if current == nil {
		s.mu.Unlock()
		return nil, 0, dns.ErrEmptyResponse
	}
	current.users++
	s.mu.Unlock()
	defer s.release(current)
	return current.client.LookupIP(domain, option)
}

func (s *reloadableDNS) release(current *dnsGeneration) {
	s.mu.Lock()
	current.users--
	close := current != s.active && current.users == 0
	if close {
		delete(s.retired, current)
	}
	s.mu.Unlock()
	if close {
		_ = current.close()
	}
}

// IsOwnLink preserves the core DNS outbound's loop check, including while a
// retired backend still has a request using its old internal inbound tag.
func (s *reloadableDNS) IsOwnLink(ctx context.Context) bool {
	check := func(g *dnsGeneration) bool {
		if g == nil {
			return false
		}
		v, ok := g.client.(interface{ IsOwnLink(context.Context) bool })
		return ok && v.IsOwnLink(ctx)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if check(s.active) {
		return true
	}
	for g := range s.retired {
		if check(g) {
			return true
		}
	}
	return false
}

func (s *reloadableDNS) MayUseSystemResolver() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return false
	}
	v, ok := s.active.client.(interface{ MayUseSystemResolver() bool })
	return !ok || v.MayUseSystemResolver()
}

type reloadablePolicy struct {
	active atomic.Pointer[apppolicy.Instance]
}

func (*reloadablePolicy) Type() any                  { return policy.ManagerType() }
func (*reloadablePolicy) Start() error               { return nil }
func (*reloadablePolicy) Close() error               { return nil }
func (p *reloadablePolicy) ForSystem() policy.System { return p.active.Load().ForSystem() }
func (p *reloadablePolicy) ForLevel(level uint32) policy.Session {
	return p.active.Load().ForLevel(level)
}

func init() {
	common.Must(common.RegisterConfig((*DNSConfig)(nil), func(ctx context.Context, raw any) (any, error) {
		gen, err := newDNSGeneration(ctx, raw.(*DNSConfig))
		if err != nil {
			return nil, err
		}
		return &reloadableDNS{active: gen}, nil
	}))
	common.Must(common.RegisterConfig((*PolicyConfig)(nil), func(ctx context.Context, raw any) (any, error) {
		compiled := new(apppolicy.Config)
		if err := proto.Unmarshal(raw.(*PolicyConfig).NativeValue, compiled); err != nil {
			return nil, err
		}
		next, err := apppolicy.New(ctx, compiled)
		if err != nil {
			return nil, err
		}
		manager := new(reloadablePolicy)
		manager.active.Store(next)
		return manager, nil
	}))
}

// Install on the startup clone, never on the immutable Prepared protobuf.
func installReloadableFeatures(compiled *core.Config) {
	hasDNS := false
	for i, msg := range compiled.App {
		switch msg.Type {
		case dnsMessageType:
			compiled.App[i] = serial.ToTypedMessage(&DNSConfig{NativeValue: msg.Value})
			hasDNS = true
		case policyMessageType:
			compiled.App[i] = serial.ToTypedMessage(&PolicyConfig{NativeValue: msg.Value})
		}
	}
	if !hasDNS {
		compiled.App = append(compiled.App, serial.ToTypedMessage(&DNSConfig{UseLocal: true}))
	}
}

func sameNonReloadableStatic(old, next *Prepared) bool {
	if old.StaticHash == next.StaticHash {
		return true
	}
	key := func(p *Prepared) [32]byte {
		native := maps.Clone(p.Native)
		delete(native, "dns")
		delete(native, "policy")
		return staticKey(native)
	}
	return key(old) == key(next)
}

func featureMessage(p *Prepared, typeName string) *serial.TypedMessage {
	for _, msg := range p.Core.App {
		if msg.Type == typeName {
			return msg
		}
	}
	return nil
}

type featureReload struct {
	dns    *reloadableDNS
	gen    *dnsGeneration
	policy *reloadablePolicy
	levels *apppolicy.Instance
}

func prepareFeatureReload(inst *core.Instance, old, next *Prepared) (*featureReload, error) {
	reload := new(featureReload)
	oldPolicy, nextPolicy := featureMessage(old, policyMessageType), featureMessage(next, policyMessageType)
	if !proto.Equal(oldPolicy, nextPolicy) {
		manager, ok := inst.GetFeature(policy.ManagerType()).(*reloadablePolicy)
		if !ok || nextPolicy == nil {
			return nil, fmt.Errorf("%w: native policy manager is unavailable", ErrReloadUnsupported)
		}
		next, err := core.CreateObject(inst, &PolicyConfig{NativeValue: nextPolicy.Value})
		if err != nil {
			return nil, fmt.Errorf("prepare native policy: %w", err)
		}
		levels := next.(*reloadablePolicy).active.Load()
		if manager.ForSystem() != levels.ForSystem() {
			return nil, fmt.Errorf("%w: native system policy is fixed by the serving handlers", ErrReloadUnsupported)
		}
		reload.policy, reload.levels = manager, levels
	}

	oldDNS, nextDNS := featureMessage(old, dnsMessageType), featureMessage(next, dnsMessageType)
	envChanged := assetReferences(next.Native["dns"], "") && sectionKey(old.Native["env"]) != sectionKey(next.Native["env"])
	if !proto.Equal(oldDNS, nextDNS) || envChanged {
		manager, ok := inst.GetFeature(dns.ClientType()).(*reloadableDNS)
		if !ok {
			return nil, fmt.Errorf("%w: native DNS manager is unavailable", ErrReloadUnsupported)
		}
		conf := &DNSConfig{UseLocal: nextDNS == nil}
		if nextDNS != nil {
			conf.NativeValue = nextDNS.Value
		}
		next, err := core.CreateObject(inst, conf)
		if err != nil {
			return nil, fmt.Errorf("prepare native DNS: %w", err)
		}
		gen := next.(*reloadableDNS).active
		if err = gen.client.Start(); err != nil {
			_ = gen.close()
			return nil, fmt.Errorf("start native DNS: %w", err)
		}
		reload.dns, reload.gen = manager, gen
	}
	return reload, nil
}

func (p *featureReload) Commit() {
	if p.policy != nil {
		p.policy.active.Store(p.levels)
	}
	if p.dns != nil {
		old := p.dns.replace(p.gen)
		p.gen = nil
		if old != nil {
			_ = old.close()
		}
	}
}

func (p *featureReload) Discard() {
	if p.gen != nil {
		_ = p.gen.close()
		p.gen = nil
	}
}
