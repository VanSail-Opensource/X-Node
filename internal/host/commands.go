// Package host runs typed Linux utilities. It never evaluates a shell command.
package host

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type Commands struct{}

func (Commands) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := CheckLinux(); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.New(name + " failed")
	}
	return out, nil
}

// CheckLinux validates the runtime platform without restricting distributions.
func CheckLinux() error {
	if runtime.GOOS != "linux" {
		return errors.New("X-Node requires Linux")
	}
	return nil
}

// CheckDebian restricts the destructive host fixture to its Debian 13 VM.
// Production agent, CLI and update paths use CheckLinux instead.
func CheckDebian() error {
	if err := CheckLinux(); err != nil {
		return err
	}
	b, e := os.ReadFile("/etc/os-release")
	if e != nil {
		return e
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			fields[k] = strings.Trim(v, "\"'")
		}
	}
	if fields["ID"] != "debian" || fields["VERSION_ID"] != "13" {
		return errors.New("X-Node requires Debian 13")
	}
	return nil
}
