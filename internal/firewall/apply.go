package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func (m *Manager) Apply(ctx context.Context, id string, p protocol.FirewallPolicy, redirect bool) (Pending, error) {
	return m.apply(ctx, id, p, redirect, redirect)
}
func (m *Manager) apply(ctx context.Context, id string, p protocol.FirewallPolicy, redirect, activeRedirect bool) (Pending, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	release, err := m.locked(ctx)
	if err != nil {
		return Pending{}, err
	}
	defer release()
	if id == "" {
		return Pending{}, errors.New("firewall transaction ID is required")
	}
	existing, err := readRecord(m.path())
	if err != nil && !os.IsNotExist(err) {
		return Pending{}, err
	}
	if err == nil {
		if existing.ID == id {
			left, _ := json.Marshal(existing.Policy)
			right, _ := json.Marshal(p)
			if !bytes.Equal(left, right) || existing.Redirect != redirect {
				return Pending{}, errors.New("firewall transaction ID reused with different inputs")
			}
			if existing.Status == "confirmed" || existing.Status == "pending" && existing.Deadline.After(time.Now()) {
				return existing.Pending, nil
			}
			if existing.Status == "pending" {
				if err := m.recover(ctx, &existing, true); err != nil {
					return Pending{}, err
				}
			}
			// Failed attempts known not to commit may be retried after transient I/O
			// failures. A timed-out or explicitly rolled-back apply stays terminal.
			if existing.Status != "failed" {
				return existing.Pending, errors.New("firewall transaction is no longer pending")
			}
		}
		if existing.Status == "pending" {
			if existing.Deadline.After(time.Now()) {
				return Pending{}, errors.New("another firewall transaction is pending")
			}
			if err := m.recover(ctx, &existing, true); err != nil {
				return Pending{}, err
			}
		}
	}
	ssh, err := m.ssh(ctx)
	if err != nil {
		return Pending{}, err
	}
	if err := validate(p, ssh); err != nil {
		return Pending{}, err
	}
	tx, err := m.prepare(ctx, id, p, redirect, ssh)
	if err != nil {
		return tx.Pending, err
	}
	tx.Deadline = time.Now().Add(45 * time.Second)
	if err = writeRecord(tx.Candidate, tx); err != nil {
		return tx.Pending, err
	}
	if err = writeRecord(m.path(), tx); err != nil {
		return tx.Pending, err
	}
	if _, err = m.Runner.Run(ctx, "systemd-run", "--unit="+tx.Unit, "--on-active=45s", "--timer-property=AccuracySec=1s", "--property=Restart=on-failure", "--property=RestartSec=5s", "--collect", m.Executable, "firewall-rollback", "--state-dir", m.Dir, "--request-id", id); err != nil {
		tx.Status = "failed"
		return tx.Pending, errors.Join(err, writeRecord(m.path(), tx))
	}
	if err = m.applyForwarding(ctx, tx.Pending); err != nil {
		return tx.Pending, errors.Join(err, m.recover(ctx, &tx, false))
	}
	if err = m.backend().Reconcile(ctx, p, activeRedirect, ssh); err != nil {
		return tx.Pending, errors.Join(err, m.recover(ctx, &tx, !errors.Is(err, errUnchanged)))
	}
	if err = m.takeControl(ctx, tx); err != nil {
		return tx.Pending, errors.Join(err, m.recover(ctx, &tx, true))
	}
	return tx.Pending, nil
}

func (m *Manager) prepare(ctx context.Context, id string, p protocol.FirewallPolicy, redirect bool, ssh []int) (record, error) {
	hash := sha256.Sum256([]byte(id))
	tx := record{Engine: 1, Pending: Pending{ID: id, Status: "pending", Deadline: time.Now().Add(45 * time.Second), Unit: "x-node-firewall-rollback-" + hex.EncodeToString(hash[:8]), Candidate: filepath.Join(m.Dir, "candidate.json"), Backup: filepath.Join(m.Dir, "rollback.nft"), ConfigPath: m.ConfigPath, Policy: p, Redirect: redirect, SSH: ssh, ConfigBackup: filepath.Join(m.Dir, "previous.conf"), PolicyBackup: filepath.Join(m.Dir, "previous-policy.json")}}
	config, err := m.backup(m.ConfigPath, tx.ConfigBackup)
	if err != nil {
		return tx, err
	}
	tx.ConfigExisted = config.Existed
	policy, err := m.backup(filepath.Join(m.Dir, "policy.json"), tx.PolicyBackup)
	if err != nil {
		return tx, err
	}
	tx.PolicyExisted = policy.Existed
	for i, target := range []string{m.unitPath(), m.dropinPath()} {
		f, err := m.backup(target, filepath.Join(m.Dir, fmt.Sprintf("previous-unit-%d", i)))
		if err != nil {
			return tx, err
		}
		tx.Files = append(tx.Files, f)
	}
	previous, err := m.Runner.Run(ctx, "nft", "list", "ruleset")
	if err != nil {
		return tx, err
	}
	native, compat, err := splitCompatTables(previous)
	if err != nil {
		return tx, err
	}
	if tx.Compat, err = m.saveCompat(ctx, compat, "rollback"); err != nil {
		return tx, err
	}
	snapshot := append([]byte("flush ruleset\n"), native...)
	if err = state.AtomicWrite(tx.Backup, snapshot, 0600); err != nil {
		return tx, err
	}
	if _, err = os.Stat(filepath.Join(m.Dir, "original.nft")); os.IsNotExist(err) {
		if err = state.AtomicWrite(filepath.Join(m.Dir, "original.nft"), snapshot, 0600); err != nil {
			return tx, err
		}
		originals, saveErr := m.saveCompat(ctx, compat, "original")
		if saveErr != nil {
			return tx, saveErr
		}
		if len(originals) > 0 {
			if err = writeOriginalCompat(m.Dir, originals); err != nil {
				return tx, err
			}
		}
	} else if err != nil {
		return tx, err
	}
	candidate, err := json.Marshal(tx)
	if err != nil {
		return tx, err
	}
	if err = state.AtomicWrite(tx.Candidate, candidate, 0600); err != nil {
		return tx, err
	}
	if err = m.prepareForwarding(ctx, &tx.Pending); err != nil {
		return tx, err
	}
	if err = m.prepareServices(ctx, &tx); err != nil {
		return tx, err
	}
	return tx, nil
}
