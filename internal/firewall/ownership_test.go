package firewall

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestHostOwnershipTakesOverEnabledAndDisabledNFTablesAndUFW(t *testing.T) {
	for _, mode := range []string{"nftables-on", "nftables-off", "ufw-on", "ufw-cli"} {
		t.Run(mode, func(t *testing.T) {
			m, f, backend := fixture(t)
			r := &serviceRunner{fakeRunner: f, states: map[string]serviceState{
				"nftables.service": {Name: "nftables.service", Enabled: "disabled"},
			}}
			if mode == "nftables-on" {
				r.states["nftables.service"] = serviceState{Name: "nftables.service", Enabled: "enabled", Active: true}
			}
			if strings.HasPrefix(mode, "ufw") {
				r.states["ufw.service"] = serviceState{Name: "ufw.service", Enabled: "enabled", Active: mode == "ufw-on"}
				m.UFWConfigPath = filepath.Join(filepath.Dir(m.Dir), "ufw.conf")
				if err := os.WriteFile(m.ufwConfig(), []byte("# preserved\nENABLED=yes\nLOGLEVEL=low\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			initial := map[string]serviceState{}
			for k, v := range r.states {
				initial[k] = v
			}
			m.Runner = r
			backend.apply = func(context.Context) error {
				if !strings.Contains(f.log(), "systemd-run") {
					t.Fatal("kernel changed without a durable watchdog")
				}
				return nil
			}
			pending := applyFixture(t, m)
			if strings.HasPrefix(mode, "ufw") {
				if backend.calls != 2 || r.states["ufw.service"].Enabled != "masked" || r.states["ufw.service"].Active {
					t.Fatal("competing firewall remained active")
				}
				if !strings.Contains(f.log(), "ufw --force disable") {
					t.Fatal("CLI-enabled UFW enforcement was not disabled")
				}
				if b, err := os.ReadFile(m.ufwConfig()); err != nil || !strings.Contains(string(b), "ENABLED=no") {
					t.Fatal("UFW would reload its policy", err)
				}
			}
			if err := m.Confirm(context.Background(), pending.ID); err != nil {
				t.Fatal(err)
			}
			if state := r.states["nftables.service"]; !state.Active || state.Enabled != "enabled" {
				t.Fatal("nftables was not enabled", state)
			}
			if err := m.RestoreOriginal(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(initial, r.states) {
				t.Fatal("uninstall lost previous service ownership", initial, r.states)
			}
			if strings.HasPrefix(mode, "ufw") {
				if b, err := os.ReadFile(m.ufwConfig()); err != nil || string(b) != "# preserved\nENABLED=yes\nLOGLEVEL=low\n" {
					t.Fatal("original UFW settings lost", err)
				}
			}
			before := f.log()
			if err := m.RestoreOriginal(context.Background()); err != nil || f.log() != before {
				t.Fatal("already unmanaged state was overwritten", err)
			}
		})
	}
}

func TestOwnershipPersistenceFailureRestoresServicesBeforeKernelSnapshot(t *testing.T) {
	m, f, _ := fixture(t)
	r := &serviceRunner{fakeRunner: f, states: map[string]serviceState{
		"nftables.service": {Name: "nftables.service", Enabled: "disabled"},
		"ufw.service":      {Name: "ufw.service", Enabled: "enabled", Active: true},
	}}
	m.Runner = r
	m.UFWConfigPath = filepath.Join(filepath.Dir(m.Dir), "ufw.conf")
	if err := os.WriteFile(m.ufwConfig(), []byte("ENABLED=yes\n"), 0644); err != nil {
		t.Fatal(err)
	}
	pending := applyFixture(t, m)
	f.fail = "systemctl enable x-node-firewall.service"
	if err := m.Confirm(context.Background(), pending.ID); err == nil {
		t.Fatal("failed boot persistence confirmed")
	}
	if !r.states["ufw.service"].Active || r.states["nftables.service"].Active || r.states["ufw.service"].Enabled != "enabled" {
		t.Fatal("rollback did not restore previous owners", r.states)
	}
	log := f.log()
	if strings.LastIndex(log, "nft -f") < strings.LastIndex(log, "systemctl start ufw.service") {
		t.Fatal("service start overwrote restored kernel rules")
	}
}

func TestRecoveryDoesNotRestartUnchangedFirewallOwners(t *testing.T) {
	m, f, _ := fixture(t)
	r := &serviceRunner{fakeRunner: f, states: map[string]serviceState{
		"nftables.service": {Name: "nftables.service", Enabled: "enabled", Active: true},
		"ufw.service":      {Name: "ufw.service", Enabled: "masked"},
	}}
	m.Runner = r
	if err := m.restoreServices(context.Background(), []serviceState{r.states["nftables.service"], r.states["ufw.service"]}); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"start", "stop", "unmask", "mask", "enable", "disable"} {
		if strings.Contains(f.log(), "systemctl "+action+" ") {
			t.Fatal("unchanged service mutated during watchdog recovery", f.log())
		}
	}
}
