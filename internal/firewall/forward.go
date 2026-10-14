package firewall

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/VanSail-Opensource/X-Node/internal/state"
)

type forwarding struct {
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
}

func (m *Manager) forwardingPath() string {
	return filepath.Join(filepath.Dir(m.ConfigPath), "sysctl.d", "90-x-node-forwarding.conf")
}
func (m *Manager) originalForwarding() (forwarding, error) {
	var p forwarding
	b, e := os.ReadFile(filepath.Join(m.Dir, "original-forwarding.json"))
	if e == nil {
		e = json.Unmarshal(b, &p)
	}
	return p, e
}
func (m *Manager) prepareForwarding(ctx context.Context, p *Pending) error {
	path := m.forwardingPath()
	b, e := os.ReadFile(path)
	if e == nil {
		p.ForwardConfigExisted = true
		if e = state.AtomicWrite(filepath.Join(m.Dir, "previous-forwarding.conf"), b, 0600); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if len(p.Policy.Forward) == 0 && !p.ForwardConfigExisted {
		return nil
	}
	v4, e := m.Runner.Run(ctx, "sysctl", "-n", "net.ipv4.ip_forward")
	if e != nil {
		return e
	}
	v6, e := m.Runner.Run(ctx, "sysctl", "-n", "net.ipv6.conf.all.forwarding")
	if e != nil {
		return e
	}
	p.ForwardIPv4 = strings.TrimSpace(string(v4))
	p.ForwardIPv6 = strings.TrimSpace(string(v6))
	if _, e = m.originalForwarding(); os.IsNotExist(e) {
		b, _ = json.Marshal(forwarding{p.ForwardIPv4, p.ForwardIPv6})
		return state.AtomicWrite(filepath.Join(m.Dir, "original-forwarding.json"), b, 0600)
	}
	return e
}
func (m *Manager) applyForwarding(ctx context.Context, p Pending) error {
	if p.ForwardIPv4 == "" {
		return nil
	}
	original, e := m.originalForwarding()
	if e != nil {
		return e
	}
	if len(p.Policy.Forward) > 0 {
		original = forwarding{"1", "1"}
	}
	_, e = m.Runner.Run(ctx, "sysctl", "-w", "net.ipv4.ip_forward="+original.IPv4, "net.ipv6.conf.all.forwarding="+original.IPv6)
	return e
}
func (m *Manager) persistForwarding(p Pending) error {
	if len(p.Policy.Forward) > 0 {
		return state.AtomicWrite(m.forwardingPath(), []byte("net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\n"), 0600)
	}
	if e := os.Remove(m.forwardingPath()); e != nil && !os.IsNotExist(e) {
		return e
	}
	return nil
}
