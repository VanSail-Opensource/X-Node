// Package localstatus exposes a bounded local query without persistent telemetry.
package localstatus

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const SocketName = "status.sock"

type Snapshot struct {
	Liveness       bool      `json:"liveness"`
	Ready          bool      `json:"ready"`
	Connected      bool      `json:"connected"`
	Revision       uint64    `json:"revision"`
	ConfigRevision uint64    `json:"config_revision"`
	Updated        time.Time `json:"updated"`
}

type Server struct {
	listener *net.UnixListener
	cancel   context.CancelFunc
	done     chan struct{}
	closed   sync.Once
}

// Listen requires the existing private state directory. A regular file or live
// socket is never replaced; stale sockets can be reclaimed after a crash.
func Listen(ctx context.Context, dir string, snapshot func() Snapshot) (*Server, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("local status requires a private state directory")
	}
	path := filepath.Join(dir, SocketName)
	if info, err = os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("local status path is not a socket")
		}
		connection, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
		if dialErr == nil {
			connection.Close()
			return nil, errors.New("local status socket is already in use")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, errors.New("cannot verify stale local status socket")
		}
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	child, cancel := context.WithCancel(ctx)
	s := &Server{listener: listener, cancel: cancel, done: make(chan struct{})}
	go s.run(child, snapshot)
	return s, nil
}

func (s *Server) run(ctx context.Context, snapshot func() Snapshot) {
	defer close(s.done)
	stop := context.AfterFunc(ctx, func() { s.listener.Close() })
	defer stop()
	// One bounded response at a time avoids unbounded local connection workers.
	for {
		connection, err := s.listener.AcceptUnix()
		if err != nil {
			return
		}
		_ = connection.SetWriteDeadline(time.Now().Add(time.Second))
		_ = json.NewEncoder(connection).Encode(snapshot())
		_ = connection.Close()
	}
}

func (s *Server) Close() error {
	s.closed.Do(s.cancel)
	<-s.done
	return nil
}
