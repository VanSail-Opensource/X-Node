package nftables

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// isReadReady reports whether the netlink connection is ready for reading.
// It uses poll with a zero timeout on the underlying raw connection.
// This allows for an efficient check of socket readiness without blocking.
// If the Conn was created with a TestDial function, it assumes readiness.
func (cc *Conn) isReadReady(conn *netlink.Conn) (bool, error) {
	if cc.TestDial != nil {
		return true, nil
	}

	rawConn, err := conn.SyscallConn()
	if err != nil {
		return false, fmt.Errorf("get raw conn: %w", err)
	}

	var ready bool
	var opErr error
	err = rawConn.Control(func(fd uintptr) {
		// A netlink socket can be allocated above FD_SETSIZE when the caller
		// holds many proxy sockets. Poll does not index a fixed-size fd set.
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		for {
			_, opErr = unix.Poll(fds, 0) // zero timeout: immediate return
			if opErr != unix.EINTR {
				break
			}
		}
		if opErr != nil {
			return
		}
		if fds[0].Revents&unix.POLLNVAL != 0 {
			opErr = unix.EBADF
			return
		}
		// Like select, expose EOF and pending socket errors to Receive instead
		// of treating them as an empty response queue.
		ready = fds[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0
	})
	if err != nil {
		return false, err
	}

	if opErr != nil {
		return false, fmt.Errorf("poll: %w", opErr)
	}

	return ready, nil
}
