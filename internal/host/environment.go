package host

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const systemPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// Named utilities resolve only in root-owned installation directories, never
// through the process PATH. Absolute paths are supplied by typed update callers
// for staged, signature-verified binaries and rollback inspection.
func systemExecutable(name string) (string, error) {
	if filepath.IsAbs(name) {
		return name, nil
	}
	if name == "" || strings.ContainsAny(name, `/\`) {
		return "", errors.New("invalid host utility")
	}
	for _, dir := range strings.Split(systemPath, ":") {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return path, nil
		}
	}
	return "", errors.New("host utility unavailable")
}

func utilityCommand(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	path, err := systemExecutable(name)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=" + systemPath, "LANG=C", "LC_ALL=C"}
	return cmd, nil
}
