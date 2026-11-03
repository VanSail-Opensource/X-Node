//go:build linux

package localstatus

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPrivateStatusQueryAndPathProtection(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	want := Snapshot{Liveness: true, Ready: true, Revision: 17, ConfigRevision: 16, Updated: time.Now().UTC()}
	server, err := Listen(context.Background(), dir, func() Snapshot { return want })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	path := filepath.Join(dir, SocketName)
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket permissions: %v, %v", info, err)
	}
	got, err := Query(context.Background(), path)
	if err != nil || got != want {
		t.Fatalf("status: %+v, %v", got, err)
	}
	if other, err := Listen(context.Background(), dir, func() Snapshot { return Snapshot{} }); err == nil {
		other.Close()
		t.Fatal("replaced a running status socket")
	}
	server.Close()
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if other, err := Listen(context.Background(), dir, func() Snapshot { return Snapshot{} }); err == nil {
		other.Close()
		t.Fatal("replaced a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "keep" {
		t.Fatal("changed unrelated status path")
	}
}

func TestStatusReclaimsOnlyAStaleSocket(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	path := filepath.Join(dir, SocketName)
	old, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	old.SetUnlinkOnClose(false)
	old.Close()
	server, err := Listen(context.Background(), dir, func() Snapshot { return Snapshot{Liveness: true} })
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if got, err := Query(context.Background(), path); err != nil || !got.Liveness {
		t.Fatalf("stale socket recovery: %+v, %v", got, err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if other, err := Listen(context.Background(), dir, func() Snapshot { return Snapshot{} }); err == nil {
		other.Close()
		t.Fatal("accepted public state directory")
	}
}
