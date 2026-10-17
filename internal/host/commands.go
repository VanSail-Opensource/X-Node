// Package host runs typed Debian utilities. It never evaluates a shell command.
package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type Commands struct{}

func (Commands) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("host utility requires Linux")
	}
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.New(name + " failed")
	}
	return out, nil
}

// CheckRequirements checks operational capabilities without a distribution gate.
func CheckRequirements() error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return errors.New("X-Node requires Linux amd64/arm64")
	}
	if os.Geteuid() != 0 {
		return errors.New("X-Node requires root privileges")
	}
	var missing []string
	for _, name := range []string{"nft", "systemctl", "systemd-run", "ss", "ip", "sshd"} {
		if _, err := exec.LookPath(name); err != nil {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required host utilities: %s", strings.Join(missing, ", "))
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("a running systemd instance is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := (Commands{}).Run(ctx, "nft", "list", "tables"); err != nil {
		return errors.New("nftables kernel support and network-administration privileges are required")
	}
	return nil
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
