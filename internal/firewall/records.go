package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type fileBackup struct {
	Target  string `json:"target"`
	Backup  string `json:"backup"`
	Existed bool   `json:"existed"`
}

// Embedded Pending keeps old disk records readable without exposing engine
// implementation details through firewall.pending or firewall.status.
type record struct {
	Pending
	Engine    int            `json:"engine,omitempty"`
	Files     []fileBackup   `json:"files,omitempty"`
	Services  []serviceState `json:"services,omitempty"`
	Ownership bool           `json:"ownership,omitempty"`
}

func (m *Manager) path() string { return filepath.Join(m.Dir, "pending.json") }
func readRecord(path string) (record, error) {
	var p record
	b, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	if p.Engine < 0 || p.Engine > 1 {
		return p, errors.New("unsupported firewall state version")
	}
	return p, nil
}
func writeRecord(path string, p record) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return state.AtomicWrite(path, b, 0600)
}
func (m *Manager) locked(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(m.Dir, 0700); err != nil {
		return nil, err
	}
	return lockContext(ctx, filepath.Join(m.Dir, "lock"))
}
func (m *Manager) ssh(ctx context.Context) ([]int, error) {
	b, err := m.Runner.Run(ctx, "sshd", "-T")
	if err != nil {
		return nil, errors.New("cannot discover SSH ports")
	}
	seen := map[int]bool{}
	var out []int
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "port" {
			continue
		}
		port, err := strconv.Atoi(fields[1])
		if err != nil || port < 1 || port > 65535 || seen[port] {
			continue
		}
		seen[port] = true
		out = append(out, port)
	}
	if len(out) == 0 {
		return nil, errors.New("no SSH port discovered")
	}
	return out, nil
}
func (m *Manager) Status() any {
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	release, err := m.locked(ctx)
	if err != nil {
		return map[string]string{"status": "error"}
	}
	defer release()
	p, err := readRecord(m.path())
	if os.IsNotExist(err) {
		return map[string]string{"status": "unmanaged"}
	}
	if err != nil {
		return map[string]string{"status": "error"}
	}
	return p.Pending
}
func (m *Manager) backup(target, path string) (fileBackup, error) {
	f := fileBackup{Target: target, Backup: path}
	b, err := os.ReadFile(target)
	if os.IsNotExist(err) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	f.Existed = true
	return f, state.AtomicWrite(path, b, 0600)
}
func restoreBackup(f fileBackup, mode os.FileMode) error {
	if !f.Existed {
		err := os.Remove(f.Target)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	b, err := os.ReadFile(f.Backup)
	if err != nil {
		return err
	}
	return state.AtomicWrite(f.Target, b, mode)
}
