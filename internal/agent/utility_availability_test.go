package agent

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/geodata"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestCancelledDDNSWaitReleasesUtilityCapacity(t *testing.T) {
	a := &Agent{}
	if err := a.dnsMu.LockContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer a.dnsMu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := a.runDDNS(ctx, protocol.Config{}, protocol.DDNSJob{ID: "wan", Provider: protocol.BuiltinDDNSProvider, IPv4: "192.0.2.1"})
		result <- err
	}()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled provider waiter did not stop", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled DDNS job waited for another provider operation")
	}
}

func TestSupersededNativeWaitDoesNotWaitForAnotherUtility(t *testing.T) {
	a := &Agent{}
	if err := a.nativeMu.LockContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer a.nativeMu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- a.activate(context.Background(), applyJob{Context: ctx}) }()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("superseded native waiter did not stop", err)
		}
	case <-time.After(time.Second):
		t.Fatal("superseded activation held its executor while waiting for a utility")
	}
}

func TestScheduledAssetDownloadDoesNotHoldNativeActivationLock(t *testing.T) {
	// A stalled TLS handshake models an unavailable provider without trusting a
	// test certificate or changing the global HTTP transport used by other jobs.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if connection, err := listener.Accept(); err == nil {
			accepted <- connection
		}
	}()
	a := &Agent{Dir: t.TempDir(), geoCandidate: "serving-candidate", geoCandidateKey: "serving-key"}
	policy := geodata.Policy{Assets: []geodata.Asset{{URL: "https://" + listener.Addr().String() + "/geosite.dat", File: "geosite.dat"}}}
	a.scheduleGeodata(policy)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.refreshGeodata(ctx, protocol.Config{}, policy) }()
	select {
	case connection := <-accepted:
		defer connection.Close()
	case err := <-done:
		t.Fatal("asset job did not start its isolated transfer", err)
	case <-time.After(3 * time.Second):
		t.Fatal("asset download did not reach fixture")
	}
	check, stopCheck := context.WithTimeout(context.Background(), time.Second)
	defer stopCheck()
	if err := a.nativeMu.LockContext(check); err != nil {
		t.Fatal("slow asset download blocked unrelated native activation", err)
	}
	a.nativeMu.Unlock()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled transfer was published")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled asset transfer did not stop")
	}
	if a.geoCandidate != "serving-candidate" || a.geoCandidateKey != "serving-key" {
		t.Fatal("failed asset transfer replaced the last candidate")
	}
	entries, err := os.ReadDir(filepath.Join(a.Dir, "geodata"))
	if err != nil || len(entries) != 0 {
		t.Fatal("failed asset transfer retained a private staging generation", err, entries)
	}
}
