package firewall

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type serviceRunner struct {
	*fakeRunner
	states map[string]serviceState
}

func (r *serviceRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	b, err := r.fakeRunner.Run(ctx, name, args...)
	if err != nil || name != "systemctl" || len(args) == 0 {
		return b, err
	}
	if args[0] == "list-unit-files" {
		var out strings.Builder
		for _, name := range []string{"nftables.service", "ufw.service"} {
			if s, ok := r.states[name]; ok {
				fmt.Fprintf(&out, "%s %s -\n", name, s.Enabled)
			}
		}
		return []byte(out.String()), nil
	}
	unit := args[len(args)-1]
	s, ok := r.states[unit]
	if !ok {
		return b, nil
	}
	if args[0] == "show" {
		active := "inactive"
		if s.Active {
			active = "active"
		}
		return []byte("ActiveState=" + active + "\n"), nil
	}
	switch args[0] {
	case "unmask":
		if strings.HasPrefix(s.Enabled, "masked") {
			s.Enabled = "disabled"
		}
	case "mask":
		s.Enabled = "masked"
		if len(args) == 3 && args[1] == "--now" {
			s.Active = false
		}
	case "enable":
		s.Enabled = "enabled"
	case "disable":
		s.Enabled = "disabled"
	case "start":
		if strings.HasPrefix(s.Enabled, "masked") {
			return nil, errors.New("masked service")
		}
		s.Active = true
	case "stop":
		s.Active = false
	}
	r.states[unit] = s
	return b, nil
}
