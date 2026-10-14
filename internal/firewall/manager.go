package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Pending struct {
	ID                   string                  `json:"id"`
	Deadline             time.Time               `json:"deadline"`
	Status               string                  `json:"status"`
	Unit                 string                  `json:"unit"`
	Candidate            string                  `json:"candidate"`
	Backup               string                  `json:"backup"`
	ConfigPath           string                  `json:"config_path"`
	Policy               protocol.FirewallPolicy `json:"policy"`
	Redirect             bool                    `json:"redirect"`
	SSH                  []int                   `json:"ssh"`
	ForwardIPv4          string                  `json:"forward_ipv4,omitempty"`
	ForwardIPv6          string                  `json:"forward_ipv6,omitempty"`
	ConfigBackup         string                  `json:"config_backup"`
	ConfigExisted        bool                    `json:"config_existed"`
	PolicyBackup         string                  `json:"policy_backup"`
	PolicyExisted        bool                    `json:"policy_existed"`
	ForwardConfigExisted bool                    `json:"forward_config_existed"`
}
type Manager struct {
	mu         sync.Mutex
	Dir        string
	ConfigPath string
	Executable string
	Runner     host.Runner
}

func (m *Manager) path() string { return filepath.Join(m.Dir, "pending.json") }
func (m *Manager) locked() (func(), error) {
	if e := os.MkdirAll(m.Dir, 0700); e != nil {
		return nil, e
	}
	return host.Lock(filepath.Join(m.Dir, "lock"))
}
func (m *Manager) Apply(ctx context.Context, id string, p protocol.FirewallPolicy, redirect bool) (Pending, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	release, e := m.locked()
	if e != nil {
		return Pending{}, e
	}
	defer release()
	if existing, e := readPending(m.path()); e == nil && existing.Status == "pending" {
		if existing.ID == id {
			return existing, nil
		}
		return Pending{}, errors.New("another firewall transaction is pending")
	}
	ssh, e := m.ssh(ctx)
	if e != nil {
		return Pending{}, e
	}
	candidate, e := Render(p, redirect, ssh)
	if e != nil {
		return Pending{}, e
	}
	hash := sha256.Sum256([]byte(id))
	key := hex.EncodeToString(hash[:8])
	pending := Pending{ID: id, Deadline: time.Now().Add(45 * time.Second), Status: "pending", Unit: "x-node-firewall-rollback-" + key, Candidate: filepath.Join(m.Dir, "candidate.nft"), Backup: filepath.Join(m.Dir, "rollback.nft"), ConfigPath: m.ConfigPath, Policy: p, Redirect: redirect, SSH: ssh}
	pending.ConfigBackup = filepath.Join(m.Dir, "previous.conf")
	pending.PolicyBackup = filepath.Join(m.Dir, "previous-policy.json")
	if b, e := os.ReadFile(m.ConfigPath); e == nil {
		pending.ConfigExisted = true
		if e = state.AtomicWrite(pending.ConfigBackup, b, 0600); e != nil {
			return pending, e
		}
	} else if !os.IsNotExist(e) {
		return pending, e
	}
	if b, e := os.ReadFile(filepath.Join(m.Dir, "policy.json")); e == nil {
		pending.PolicyExisted = true
		if e = state.AtomicWrite(pending.PolicyBackup, b, 0600); e != nil {
			return pending, e
		}
	} else if !os.IsNotExist(e) {
		return pending, e
	}
	if e = state.AtomicWrite(pending.Candidate, candidate, 0600); e != nil {
		return pending, e
	}
	if _, e = m.Runner.Run(ctx, "nft", "-c", "-f", pending.Candidate); e != nil {
		return pending, e
	}
	previous, e := m.Runner.Run(ctx, "nft", "list", "ruleset")
	if e != nil {
		return pending, e
	}
	if e = state.AtomicWrite(pending.Backup, append([]byte("flush ruleset\n"), previous...), 0600); e != nil {
		return pending, e
	}
	if _, e = os.Stat(filepath.Join(m.Dir, "original.nft")); os.IsNotExist(e) {
		if e = state.AtomicWrite(filepath.Join(m.Dir, "original.nft"), append([]byte("flush ruleset\n"), previous...), 0600); e != nil {
			return pending, e
		}
	}
	if e = m.prepareForwarding(ctx, &pending); e != nil {
		return pending, e
	}
	if e = writePending(m.path(), pending); e != nil {
		return pending, e
	}
	if _, e = m.Runner.Run(ctx, "systemd-run", "--unit="+pending.Unit, "--on-active=45s", "--collect", m.Executable, "firewall-rollback", "--state-dir", m.Dir, "--request-id", id); e != nil {
		pending.Status = "failed"
		_ = writePending(m.path(), pending)
		return pending, e
	}
	{
		if e = m.applyForwarding(ctx, pending); e != nil {
			_ = m.rollback(ctx, &pending)
			return pending, e
		}
	}
	if _, e = m.Runner.Run(ctx, "nft", "-f", pending.Candidate); e != nil {
		_ = m.rollback(ctx, &pending)
		return pending, e
	}
	return pending, nil
}
func (m *Manager) Confirm(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	release, e := m.locked()
	if e != nil {
		return e
	}
	defer release()
	p, e := readPending(m.path())
	if e != nil {
		return e
	}
	if p.ID != id {
		return errors.New("firewall confirmation ID differs")
	}
	if p.Status == "confirmed" {
		return nil
	}
	if p.Status != "pending" || !p.Deadline.After(time.Now()) {
		_ = m.rollback(ctx, &p)
		return errors.New("firewall confirmation expired")
	}
	b, e := os.ReadFile(p.Candidate)
	if e != nil {
		return e
	}
	if e = state.AtomicWrite(m.ConfigPath, b, 0600); e != nil {
		return e
	}
	if e = m.persistForwarding(p); e != nil {
		return e
	}
	if _, e = m.Runner.Run(ctx, "systemctl", "enable", "nftables.service"); e != nil {
		return e
	}
	policyJSON, _ := json.Marshal(p)
	if e = state.AtomicWrite(filepath.Join(m.Dir, "policy.json"), policyJSON, 0600); e != nil {
		return e
	}
	p.Status = "confirmed"
	if e = writePending(m.path(), p); e != nil {
		return e
	}
	_, _ = m.Runner.Run(ctx, "systemctl", "stop", p.Unit+".timer")
	return nil
}
func (m *Manager) Rollback(ctx context.Context) error {
	return m.RollbackID(ctx, "")
}
func (m *Manager) RollbackID(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	release, e := m.locked()
	if e != nil {
		return e
	}
	defer release()
	p, e := readPending(m.path())
	if e != nil {
		return e
	}
	if p.Status != "pending" {
		return nil
	}
	if id != "" && p.ID != id {
		return nil
	}
	return m.rollback(ctx, &p)
}
func (m *Manager) rollback(ctx context.Context, p *Pending) error {
	if _, e := m.Runner.Run(ctx, "nft", "-f", p.Backup); e != nil {
		return e
	}
	if p.ForwardIPv4 != "" && p.ForwardIPv6 != "" {
		if _, e := m.Runner.Run(ctx, "sysctl", "-w", "net.ipv4.ip_forward="+p.ForwardIPv4, "net.ipv6.conf.all.forwarding="+p.ForwardIPv6); e != nil {
			return e
		}
	}
	for _, backup := range []struct {
		target, path string
		existed      bool
	}{{m.ConfigPath, p.ConfigBackup, p.ConfigExisted}, {filepath.Join(m.Dir, "policy.json"), p.PolicyBackup, p.PolicyExisted}, {m.forwardingPath(), filepath.Join(m.Dir, "previous-forwarding.conf"), p.ForwardConfigExisted}} {
		if backup.existed {
			b, e := os.ReadFile(backup.path)
			if e != nil {
				return e
			}
			if e = state.AtomicWrite(backup.target, b, 0600); e != nil {
				return e
			}
		} else {
			if e := os.Remove(backup.target); e != nil && !os.IsNotExist(e) {
				return e
			}
		}
	}
	p.Status = "rolled_back"
	return writePending(m.path(), *p)
}
func (m *Manager) RestoreFile(ctx context.Context) error {
	b, e := os.ReadFile(filepath.Join(m.Dir, "policy.json"))
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	var p Pending
	if json.Unmarshal(b, &p) != nil {
		return errors.New("invalid confirmed firewall policy")
	}
	rules, e := Render(p.Policy, false, p.SSH)
	if e != nil {
		return e
	}
	return state.AtomicWrite(m.ConfigPath, rules, 0600)
}
func (m *Manager) RestoreOriginal(ctx context.Context) error {
	path := filepath.Join(m.Dir, "original.nft")
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if _, e = m.Runner.Run(ctx, "nft", "-f", path); e != nil {
		return e
	}
	if original, e := m.originalForwarding(); e == nil {
		if _, e = m.Runner.Run(ctx, "sysctl", "-w", "net.ipv4.ip_forward="+original.IPv4, "net.ipv6.conf.all.forwarding="+original.IPv6); e != nil {
			return e
		}
		if e = os.Remove(m.forwardingPath()); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	return state.AtomicWrite(m.ConfigPath, b, 0600)
}
func (m *Manager) Status() any {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, e := readPending(m.path())
	if e != nil {
		return map[string]string{"status": "unmanaged"}
	}
	return p
}
func (m *Manager) ssh(ctx context.Context) ([]int, error) {
	b, e := m.Runner.Run(ctx, "sshd", "-T")
	if e != nil {
		return nil, errors.New("cannot discover SSH ports")
	}
	seen := map[int]bool{}
	var out []int
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "port" {
			p, e := strconv.Atoi(fields[1])
			if e == nil && p > 0 && p <= 65535 && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no SSH port discovered")
	}
	return out, nil
}
func readPending(path string) (Pending, error) {
	var p Pending
	b, e := os.ReadFile(path)
	if e != nil {
		return p, e
	}
	e = json.Unmarshal(b, &p)
	return p, e
}
func writePending(path string, p Pending) error {
	b, e := json.Marshal(p)
	if e != nil {
		return e
	}
	return state.AtomicWrite(path, b, 0600)
}
