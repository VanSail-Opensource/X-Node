package update

import (
	"log/slog"
	"os"
)

// pruneDownloads runs under the transaction lock. Keep the installed pair and
// both .old rollback dependencies; only disposable staged executables are owned.
func (m *Manager) pruneDownloads() {
	for _, path := range []string{m.NodePath, m.CLIPath} {
		if path == "" {
			continue
		}
		if err := os.Remove(path + ".new"); err != nil && !os.IsNotExist(err) {
			slog.Warn("staged upgrade cleanup pending", "error_code", "UPDATE_CLEANUP_PENDING")
		}
	}
}
