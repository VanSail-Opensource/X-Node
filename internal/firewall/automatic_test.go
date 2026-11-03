package firewall

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type automaticKernel struct {
	*guardKernel
	entries map[string]time.Time
	writes  int
	fail    bool
}

func (k *automaticKernel) AutomaticExisting(context.Context) ([]protocol.FirewallExemption, error) {
	var result []protocol.FirewallExemption
	for ip, until := range k.entries {
		result = append(result, protocol.FirewallExemption{IP: ip, Until: until})
	}
	return result, nil
}
func (k *automaticKernel) Automatic(_ context.Context, items []protocol.FirewallExemption) error {
	if k.fail {
		return errors.New("kernel unavailable")
	}
	k.writes++
	for _, item := range items {
		k.entries[item.IP] = item.Until
	}
	return nil
}

func TestAutomaticLeasesPreservePriorEpochAndIndependentGrants(t *testing.T) {
	g, base := guardFixture(t)
	at := time.Now().UTC()
	kernel := &automaticKernel{guardKernel: base, entries: map[string]time.Time{"9.9.9.19": at.Add(3 * time.Hour)}}
	g.manager.Backend = kernel
	grant := func(epoch, ip string, sequence uint64, until time.Time) error {
		_, err := g.GrantAutomatic(context.Background(), protocol.AutomaticLeaseUpdate{Epoch: epoch, Leases: []protocol.AutomaticLeaseGrant{{IP: ip, Generation: sequence, Until: until}}})
		return err
	}
	for range 2 {
		if err := grant("first", "9.9.9.19", 1, at.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if kernel.writes != 1 || !kernel.entries["9.9.9.19"].Equal(at.Add(3*time.Hour)) {
		t.Fatal("replay duplicated a grant or process restart lost its deadline", kernel.entries, kernel.writes)
	}
	ip := "2001:4860::19"
	if err := grant("first", ip, 2, at.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := grant("first", ip, 3, at.Add(2*time.Hour)); err != nil || !kernel.entries[ip].Equal(at.Add(2*time.Hour)) {
		t.Fatal("same-epoch duration reduction ignored", err, kernel.entries[ip])
	}
	if err := grant("second", ip, 1, at.Add(time.Hour)); err != nil || !kernel.entries[ip].Equal(at.Add(2*time.Hour)) {
		t.Fatal("master restart shortened a previously delivered exemption", err)
	}
	before := kernel.writes
	if err := grant("second", ip, 1, at.Add(30*time.Minute)); err == nil || kernel.writes != before {
		t.Fatal("conflicting same-generation deadline changed the kernel")
	}
	g.mu.Lock()
	g.state.Exemptions["1.1.1.1"] = protocol.FirewallExemption{IP: "1.1.1.1", Generation: "manual", Until: at.Add(4 * time.Hour)}
	if !g.exempt(netip.MustParseAddr(ip), at) || g.exempt(netip.MustParseAddr("2001:4860::20"), at) {
		t.Fatal("exact IPv6 grant exempted a neighbor or failed inside a shared range")
	}
	if err := g.compact(); err != nil {
		t.Fatal(err)
	}
	g.automatic.prune(at.Add(3 * time.Hour))
	if len(g.automatic.entries)+len(g.automatic.expiry) != 0 || !g.exempt(netip.MustParseAddr("1.1.1.1"), at.Add(3*time.Hour)) {
		t.Fatal("local expiry retained automatic state or removed a manual grant")
	}
	g.mu.Unlock()
	if err := filepath.WalkDir(g.dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err == nil && strings.HasSuffix(path, ".gz") {
			reader, openErr := gzip.NewReader(bytes.NewReader(data))
			if openErr != nil {
				return openErr
			}
			data, err = io.ReadAll(reader)
			reader.Close()
		}
		if err == nil && (strings.Contains(string(data), ip) || strings.Contains(string(data), "9.9.9.19")) {
			t.Fatal("volatile grant entered durable firewall files", path)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAutomaticLeaseKernelFailureDoesNotAcknowledgeOrPublish(t *testing.T) {
	g, base := guardFixture(t)
	kernel := &automaticKernel{guardKernel: base, entries: map[string]time.Time{}, fail: true}
	g.manager.Backend = kernel
	update := protocol.AutomaticLeaseUpdate{Epoch: "master", Leases: []protocol.AutomaticLeaseGrant{{IP: "9.9.9.19", Generation: 1, Until: time.Now().Add(time.Hour)}}}
	if _, err := g.GrantAutomatic(context.Background(), update); err == nil || len(g.automatic.entries) != 0 {
		t.Fatal("failed kernel update published an in-memory grant", err)
	}
	kernel.fail = false
	if ack, err := g.GrantAutomatic(context.Background(), update); err != nil || ack.Generation != 1 || len(g.automatic.entries) != 1 {
		t.Fatal("retry did not converge", ack, err)
	}
}
