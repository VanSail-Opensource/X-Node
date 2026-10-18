package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"golang.org/x/mod/semver"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const Repository = "VanSail-Opensource/X-Node"

type Release struct {
	Version   string `json:"version"`
	Current   string `json:"current"`
	Available bool   `json:"available"`
}
type Transaction struct {
	ID       string    `json:"id"`
	Version  string    `json:"version"`
	Previous string    `json:"previous"`
	Status   string    `json:"status"`
	Deadline time.Time `json:"deadline"`
	Unit     string    `json:"unit"`
	NodePath string    `json:"node_path"`
	CLIPath  string    `json:"cli_path"`
}
type Manager struct {
	mu       sync.Mutex
	Dir      string
	Current  string
	Runner   host.Runner
	Client   *http.Client
	NodePath string
	CLIPath  string
}

func New(dir, current string, runner host.Runner) *Manager {
	return &Manager{Dir: dir, Current: current, Runner: runner, Client: &http.Client{Timeout: 2 * time.Minute}, NodePath: "/usr/local/bin/x-node", CLIPath: "/usr/local/bin/xnodectl"}
}
func (m *Manager) fetch(ctx context.Context, url string, max int64) ([]byte, error) {
	request, e := http.NewRequestWithContext(ctx, "GET", url, nil)
	if e != nil {
		return nil, errors.New("invalid release URL")
	}
	request.Header.Set("User-Agent", "X-Node")
	response, e := m.Client.Do(request)
	if e != nil {
		return nil, errors.New("release download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("release endpoint returned status %d", response.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(response.Body, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, errors.New("release artifact exceeds size limit")
	}
	return b, nil
}
func (m *Manager) Check(ctx context.Context, version string) (Release, error) {
	result := Release{Current: m.Current}
	endpoint := "https://api.github.com/repos/" + Repository + "/releases/latest"
	if version != "" {
		if !stableVersion.MatchString(version) {
			return result, errors.New("updates require a stable version tag")
		}
		endpoint = "https://api.github.com/repos/" + Repository + "/releases/tags/" + version
	}
	b, e := m.fetch(ctx, endpoint, 1<<20)
	if e != nil {
		return result, e
	}
	var response struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if json.Unmarshal(b, &response) != nil || response.Draft || response.Prerelease || !stableVersion.MatchString(response.Tag) {
		return result, errors.New("release is not a published stable version")
	}
	result.Version = response.Tag
	result.Available = !semver.IsValid(m.Current) || semver.Compare(result.Version, m.Current) > 0
	return result, nil
}
func (m *Manager) Install(ctx context.Context, id, version string, progress func(any)) (Release, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result, e := m.Check(ctx, version)
	if e != nil {
		return result, e
	}
	if !result.Available {
		return result, nil
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return result, errors.New("binary upgrades require Linux amd64/arm64")
	}
	if e = host.CheckRequirements(); e != nil {
		return result, e
	}
	if _, e = PublicKey(); e != nil {
		return result, e
	}
	if e = os.MkdirAll(m.Dir, 0700); e != nil {
		return result, e
	}
	unlock, e := host.Lock(filepath.Join(m.Dir, "lock"))
	if e != nil {
		return result, e
	}
	defer unlock()
	if t, e := m.read(); e == nil && t.Status == "pending" {
		return result, errors.New("another upgrade is pending")
	}
	base := "https://github.com/" + Repository + "/releases/download/" + result.Version + "/"
	progress(map[string]string{"stage": "verify_manifest"})
	manifest, e := m.fetch(ctx, base+"SHA256SUMS", 1<<20)
	if e != nil {
		return result, e
	}
	signature, e := m.fetch(ctx, base+"SHA256SUMS.minisig", 4096)
	if e != nil {
		return result, e
	}
	hashes, e := Verify(manifest, signature, result.Version)
	if e != nil {
		return result, e
	}
	targets := []string{m.NodePath, m.CLIPath}
	names := []string{"x-node-linux-" + runtime.GOARCH, "xnodectl-linux-" + runtime.GOARCH}
	for i, name := range names {
		hash := hashes[name]
		if hash == "" {
			return result, errors.New("signed manifest lacks target binary")
		}
		progress(map[string]string{"stage": "download", "artifact": name})
		b, e := m.fetch(ctx, base+name, 256<<20)
		if e != nil {
			return result, e
		}
		staged := targets[i] + ".new"
		if e = state.AtomicWrite(staged, b, 0600); e != nil {
			return result, e
		}
		if e = VerifyFile(staged, hash); e != nil {
			return result, e
		}
		if e = os.Chmod(staged, 0755); e != nil {
			return result, e
		}
		out, e := m.Runner.Run(ctx, staged, "--version")
		if e != nil {
			return result, e
		}
		var info struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(out, &info) != nil || info.Version != result.Version {
			return result, errors.New("staged binary version differs")
		}
		if i == 0 {
			if e = m.checkCapabilities(out); e != nil {
				return result, e
			}
		}
	}
	for _, target := range targets {
		old, e := os.ReadFile(target)
		if e != nil {
			return result, e
		}
		if e = state.AtomicWrite(target+".old", old, 0755); e != nil {
			return result, e
		}
	}
	transaction := Transaction{ID: id, Version: result.Version, Previous: m.Current, Status: "pending", Deadline: time.Now().Add(45 * time.Second), Unit: "x-node-upgrade-rollback", NodePath: m.NodePath, CLIPath: m.CLIPath}
	if e = m.write(transaction); e != nil {
		return result, e
	}
	if _, e = m.Runner.Run(ctx, "systemd-run", "--unit="+transaction.Unit, "--on-active=45s", "--collect", m.CLIPath+".old", "upgrade-rollback", "--state-dir", m.Dir); e != nil {
		transaction.Status = "failed"
		_ = m.write(transaction)
		return result, e
	}
	for _, target := range targets {
		if e = os.Rename(target+".new", target); e != nil {
			_ = m.rollback(ctx, &transaction)
			return result, e
		}
	}
	progress(map[string]string{"stage": "restart"})
	if e = m.restart(ctx); e != nil {
		_ = m.rollback(ctx, &transaction)
		return result, e
	}
	return result, nil
}
func (m *Manager) Confirm(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := os.MkdirAll(m.Dir, 0700); e != nil {
		return e
	}
	unlock, e := host.Lock(filepath.Join(m.Dir, "lock"))
	if e != nil {
		return e
	}
	defer unlock()
	t, e := m.read()
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if t.Status != "pending" || t.Version != m.Current {
		return nil
	}
	t.Status = "confirmed"
	if e = m.write(t); e != nil {
		return e
	}
	_, _ = m.Runner.Run(ctx, "systemctl", "stop", t.Unit+".timer")
	return nil
}
func (m *Manager) Rollback(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, e := host.Lock(filepath.Join(m.Dir, "lock"))
	if e != nil {
		return e
	}
	defer unlock()
	t, e := m.read()
	if e != nil {
		return e
	}
	if t.Status == "rolled_back" || t.Status == "failed" {
		return nil
	}
	return m.rollback(ctx, &t)
}
func (m *Manager) RollbackPending(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, e := host.Lock(filepath.Join(m.Dir, "lock"))
	if e != nil {
		return e
	}
	defer unlock()
	t, e := m.read()
	if e != nil {
		return e
	}
	if t.Status != "pending" {
		return nil
	}
	return m.rollback(ctx, &t)
}
func (m *Manager) rollback(ctx context.Context, t *Transaction) error {
	if required, err := m.requiredCapabilities(); err != nil {
		return err
	} else if len(required) > 0 {
		metadata, err := m.Runner.Run(ctx, t.NodePath+".old", "--version")
		if err != nil {
			return err
		}
		if err = m.checkCapabilities(metadata); err != nil {
			return err
		}
	}
	for _, target := range []string{t.NodePath, t.CLIPath} {
		b, e := os.ReadFile(target + ".old")
		if e != nil {
			return e
		}
		if e = state.AtomicWrite(target, b, 0755); e != nil {
			return e
		}
	}
	t.Status = "rolled_back"
	if e := m.write(*t); e != nil {
		return e
	}
	return m.restart(ctx)
}
func (m *Manager) read() (Transaction, error) {
	var t Transaction
	b, e := os.ReadFile(filepath.Join(m.Dir, "transaction.json"))
	if e != nil {
		return t, e
	}
	e = json.Unmarshal(b, &t)
	return t, e
}
func (m *Manager) write(t Transaction) error {
	b, e := json.Marshal(t)
	if e != nil {
		return e
	}
	return state.AtomicWrite(filepath.Join(m.Dir, "transaction.json"), b, 0600)
}
func (m *Manager) Status() any {
	// AtomicWrite publishes a complete transaction. Observers must not wait for
	// the install lock: shutdown and the next hello both need this state.
	t, e := m.read()
	if e != nil {
		return map[string]string{"status": "idle"}
	}
	return t
}

func (m *Manager) restart(ctx context.Context) error {
	// Waiting for our own stop job would wait for the goroutine issuing it.
	// The persisted transaction and independent rollback timer survive exit.
	_, err := m.Runner.Run(ctx, "systemctl", "--no-block", "restart", "x-node.service")
	return err
}
