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
