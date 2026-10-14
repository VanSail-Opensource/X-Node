// Package host runs typed Debian utilities. It never evaluates a shell command.
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
	if runtime.GOOS != "linux" {
		return nil, errors.New("host utility requires Debian 13")
	}
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.New(name + " failed")
	}
	return out, nil
}
func CheckDebian() error {
	if runtime.GOOS != "linux" {
		return errors.New("X-Node supports Debian 13 only")
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
