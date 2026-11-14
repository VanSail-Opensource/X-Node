// Copyright 2026 The X-Node Authors. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package nftables

import (
	"errors"
	"os"
	"syscall"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// readinessSocket exposes a real raw socket through netlink's test constructor.
// No message operation is used by isReadReady, so these tests need no netlink
// privileges and cannot change the host firewall.
type readinessSocket struct {
	netlink.Socket
	raw syscall.RawConn
}

func (s readinessSocket) SyscallConn() (syscall.RawConn, error) { return s.raw, nil }

func TestSocketReadinessHighDescriptor(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(pair[0]) })
	t.Cleanup(func() {
		if pair[1] >= 0 {
			_ = unix.Close(pair[1])
		}
	})

	// Duplicate only one descriptor: no descriptor exhaustion, process-wide
	// resource-limit change, or privileged firewall operation is necessary.
	high, err := unix.FcntlInt(uintptr(pair[0]), unix.F_DUPFD_CLOEXEC, unix.FD_SETSIZE)
	if err != nil {
		t.Fatalf("duplicate socket above FD_SETSIZE (test needs nofile > 1024): %v", err)
	}
	file := os.NewFile(uintptr(high), "nftables-readiness-high-fd")
	t.Cleanup(func() { _ = file.Close() })
	if high < unix.FD_SETSIZE {
		t.Fatalf("regression did not use a high descriptor: %d", high)
	}
	t.Logf("checking real socket descriptor %d (FD_SETSIZE=%d)", high, unix.FD_SETSIZE)
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	conn := netlink.NewConn(readinessSocket{raw: raw}, 0)
	check := func(want bool) {
		t.Helper()
		got, err := (&Conn{}).isReadReady(conn)
		if err != nil || got != want {
			t.Fatalf("readiness = %t, %v; want %t, nil", got, err, want)
		}
	}

	check(false)
	if n, err := unix.Write(pair[1], []byte{0x7f}); err != nil || n != 1 {
		t.Fatalf("write = %d, %v", n, err)
	}
	check(true)
	var data [1]byte
	if n, err := unix.Read(high, data[:]); err != nil || n != 1 || data[0] != 0x7f {
		t.Fatalf("read = %d, %v, %x", n, err, data)
	}
	check(false)

	if err := unix.Close(pair[1]); err != nil {
		t.Fatal(err)
	}
	pair[1] = -1
	check(true) // EOF/HUP must remain readable, not look like an empty queue.
	if n, err := unix.Read(high, data[:]); err != nil || n != 0 {
		t.Fatalf("EOF read = %d, %v", n, err)
	}

	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	// RawConn.Control propagates its platform error; its identity need not be
	// os.ErrClosed. A closed descriptor must still be unreadable with an error.
	if ready, err := (&Conn{}).isReadReady(conn); ready || err == nil {
		t.Fatalf("closed connection = %t, %v; want false and a non-nil error", ready, err)
	}
}

// A raw-connection stub is used only to exercise poll's invalid-descriptor
// result; the high-descriptor regression above always uses a live socket.
type invalidReadinessRaw struct{ syscall.RawConn }

func (invalidReadinessRaw) Control(fn func(uintptr)) error {
	fn(1<<31 - 1)
	return nil
}

func TestSocketReadinessInvalidDescriptor(t *testing.T) {
	conn := netlink.NewConn(readinessSocket{raw: invalidReadinessRaw{}}, 0)
	if ready, err := (&Conn{}).isReadReady(conn); ready || !errors.Is(err, unix.EBADF) {
		t.Fatalf("invalid descriptor = %t, %v; want EBADF", ready, err)
	}
}
