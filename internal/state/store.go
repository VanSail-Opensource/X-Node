// Package state persists private accepted state and a bounded acknowledged traffic journal.
package state

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

const MaxStoreBytes = 64 << 20

type Traffic = protocol.Traffic
type Batch = protocol.TrafficReport
type Data struct {
	AgentID        string                            `json:"agent_id"`
	Revision       uint64                            `json:"revision"`
	ConfigRevision uint64                            `json:"config_revision"`
	Config         *protocol.Config                  `json:"config,omitempty"`
	Users          []protocol.User                   `json:"users"`
	Bans           map[int]time.Time                 `json:"bans,omitempty"`
	IPBlocks       map[string]protocol.IPBlock       `json:"ip_blocks,omitempty"`
	Sequence       uint64                            `json:"sequence"`
	Pending        *Batch                            `json:"pending,omitempty"`
	Accumulated    Traffic                           `json:"accumulated,omitempty"`
	Accounting     map[string]protocol.TrafficSample `json:"accounting,omitempty"`
	Backlog        []*Batch                          `json:"backlog,omitempty"`
}
type Store struct {
	mu   sync.Mutex
	path string
	data Data
}

func ID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "state.json")}
	b, err := os.ReadFile(s.path)
	if err == nil {
		if len(b) > MaxStoreBytes || json.Unmarshal(b, &s.data) != nil || s.data.AgentID == "" {
			return nil, errors.New("invalid persisted state")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if clean, changed := withoutConnectionControls(s.data); changed {
		s.data = clean
		if err := s.persist(clean); err != nil {
			return nil, err
		}
	}
	if s.data.AgentID == "" {
		s.data = Data{AgentID: ID(), Users: []protocol.User{}}
		if err := s.persist(s.data); err != nil {
			return nil, err
		}
	}
	if s.data.Bans == nil {
		s.data.Bans = map[int]time.Time{}
	}
	if s.data.Accumulated == nil {
		s.data.Accumulated = Traffic{}
	}
	return s, nil
}
func (s *Store) Snapshot() Data { s.mu.Lock(); defer s.mu.Unlock(); return protocol.Clone(s.data) }
func (s *Store) change(fn func(*Data) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := protocol.Clone(s.data)
	if err := fn(&next); err != nil {
		return err
	}
	if err := s.persist(next); err != nil {
		return err
	}
	s.data = next
	return nil
}
func (s *Store) persist(d Data) error {
	d, _ = withoutConnectionControls(d)
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if len(b) > MaxStoreBytes {
		return errors.New("durable state capacity exhausted")
	}
	return AtomicWrite(s.path, b, 0600)
}
func (s *Store) Authorize(users []protocol.User, revision uint64) error {
	return s.change(func(d *Data) error {
		if revision <= d.Revision {
			return errors.New("stale revision")
		}
		d.Users = protocol.Clone(users)
		if d.Users == nil {
			d.Users = []protocol.User{}
		}
		d.Revision = revision
		return nil
	})
}
func (s *Store) Accept(c protocol.Config, revision uint64) error {
	return s.change(func(d *Data) error {
		if revision != d.Revision {
			return errors.New("authorization revision changed")
		}
		c.Users = protocol.Clone(d.Users)
		d.Config = &c
		d.ConfigRevision = revision
		return nil
	})
}
func (s *Store) Ban(id int, until time.Time) error {
	return s.change(func(d *Data) error {
		if d.Bans == nil {
			d.Bans = map[int]time.Time{}
		}
		if until.IsZero() {
			delete(d.Bans, id)
		} else {
			d.Bans[id] = until
		}
		return nil
	})
}
func (s *Store) BlockIP(key string, block protocol.IPBlock) error {
	return s.change(func(d *Data) error {
		if d.IPBlocks == nil {
			d.IPBlocks = map[string]protocol.IPBlock{}
		}
		if block.Until.IsZero() {
			delete(d.IPBlocks, key)
			return nil
		}
		if len(d.IPBlocks) >= 4096 {
			if _, exists := d.IPBlocks[key]; !exists {
				return errors.New("IP block capacity exhausted")
			}
		}
		d.IPBlocks[key] = block
		return nil
	})
}
func AtomicWrite(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".xnode-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	if d, e := os.Open(filepath.Dir(path)); e == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
