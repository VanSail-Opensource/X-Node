package firewall

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type serviceState struct {
	Name    string `json:"name"`
	Enabled string `json:"enabled"`
	Active  bool   `json:"active"`
}

func (m *Manager) serviceStates(ctx context.Context) ([]serviceState, error) {
	out, err := m.Runner.Run(ctx, "systemctl", "list-unit-files", "--no-legend", "--no-pager", "nftables.service", "ufw.service")
	if err != nil {
		return nil, errors.New("cannot inspect host firewall services")
	}
	states := []serviceState{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nftables.service" && fields[0] != "ufw.service" {
			continue
		}
		switch fields[1] {
		case "enabled", "enabled-runtime", "disabled", "masked", "masked-runtime", "static", "indirect":
		default:
			return nil, fmt.Errorf("unsupported %s unit state %s", fields[0], fields[1])
		}
		raw, err := m.Runner.Run(ctx, "systemctl", "show", "--property=ActiveState", fields[0])
		if err != nil {
			return nil, fmt.Errorf("cannot inspect %s activity", fields[0])
		}
		active := strings.TrimSpace(strings.TrimPrefix(string(raw), "ActiveState="))
		if active != "active" && active != "inactive" && active != "failed" {
			return nil, fmt.Errorf("%s is transitioning; retry after it settles", fields[0])
		}
		states = append(states, serviceState{Name: fields[0], Enabled: fields[1], Active: active == "active"})
	}
	return states, nil
}

// Restore service ownership before replaying the kernel snapshot: stopping
// nftables or starting UFW may itself change the host's rules.
func (m *Manager) restoreServices(ctx context.Context, states []serviceState) error {
	for _, s := range states {
		if s.Name != "nftables.service" && s.Name != "ufw.service" {
			return errors.New("invalid saved firewall service")
		}
		for _, args := range [][]string{{"unmask", s.Name}, {"unmask", "--runtime", s.Name}} {
			if _, err := m.Runner.Run(ctx, "systemctl", args...); err != nil {
				return err
			}
		}
		var args []string
		switch s.Enabled {
		case "enabled":
			args = []string{"enable", s.Name}
		case "enabled-runtime":
			args = []string{"disable", s.Name}
		case "disabled", "masked", "masked-runtime":
			args = []string{"disable", s.Name}
		case "static", "indirect":
		default:
			return errors.New("invalid saved firewall service state")
		}
		if args != nil {
			if _, err := m.Runner.Run(ctx, "systemctl", args...); err != nil {
				return err
			}
		}
		if s.Enabled == "enabled-runtime" {
			if _, err := m.Runner.Run(ctx, "systemctl", "enable", "--runtime", s.Name); err != nil {
				return err
			}
		}
		action := "stop"
		if s.Active {
			action = "start"
		}
		if _, err := m.Runner.Run(ctx, "systemctl", action, s.Name); err != nil {
			return err
		}
		if strings.HasPrefix(s.Enabled, "masked") {
			args = []string{"mask", s.Name}
			if s.Enabled == "masked-runtime" {
				args = []string{"mask", "--runtime", s.Name}
			}
			if _, err := m.Runner.Run(ctx, "systemctl", args...); err != nil {
				return err
			}
		}
	}
	return nil
}
