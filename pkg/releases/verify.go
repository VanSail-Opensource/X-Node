// Package releases exposes the agent's pinned release trust policy to masters.
package releases

import "github.com/VanSail-Opensource/X-Node/internal/update"

func PublicKey() ([]byte, error) { return update.PublicKey() }

// Verify accepts only the project's trusted, version-bound minisign manifest.
func Verify(manifest, signature []byte, version string) (map[string]string, error) {
	return update.Verify(manifest, signature, version)
}
