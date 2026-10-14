//go:build !linux

package host

import (
	"os"
)

// Only used by portable fixture tests; deployed agents use kernel-backed flock.
func Lock(path string) (func(), error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	return func() { _ = f.Close(); _ = os.Remove(path) }, nil
}
