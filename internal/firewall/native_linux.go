package firewall

import (
	"context"
	"errors"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"log/slog"
	"syscall"
	"time"
)

type nativeBackend struct{ dir string }

// Each operation has a private socket. Cancellation interrupts I/O, including
// Flush; the durable watchdog handles the ambiguous committed-without-ACK case.
func connection(ctx context.Context) (*nftables.Conn, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	c, err := nftables.New(nftables.AsLasting(), nftables.WithSockOptions(func(n *netlink.Conn) error {
		if err := n.SetReadBuffer(1 << 20); err != nil {
			return err
		}
		if err := n.SetWriteBuffer(1 << 20); err != nil {
			return err
		}
		deadline := time.Now().Add(10 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		return n.SetDeadline(deadline)
	}))
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = c.CloseLasting() })
	return c, func() { stop(); _ = c.CloseLasting() }, nil
}
func (b nativeBackend) Reconcile(ctx context.Context, p protocol.FirewallPolicy, redirect bool, ssh []int) error {
	if err := prepareCountrySets(ctx, b.dir, p.SourceGeoIP); err != nil {
		return err
	}
	if err := reconcileNative(ctx, p, redirect, ssh); err != nil {
		return err
	}
	if keep, err := activeCountrySets(ctx); err == nil {
		if err = cleanupCountrySets(ctx, keep); err != nil {
			slog.Warn("country set cleanup pending", "error_code", "FIREWALL_CLEANUP_PENDING")
		}
	}
	return nil
}
func reconcileNative(ctx context.Context, p protocol.FirewallPolicy, redirect bool, ssh []int) (result error) {
	flushed := false
	defer func() {
		if result != nil && !flushed {
			result = errors.Join(errUnchanged, result)
		}
	}()
	plan, err := compile(p, redirect, ssh)
	if err != nil {
		return err
	}
	c, close, err := connection(ctx)
	if err != nil {
		return err
	}
	defer close()
	tables, err := c.ListTables()
	if err != nil {
		return err
	}
	exists := false
	for _, t := range tables {
		if t.Name == plan.table.Name && t.Family == plan.table.Family {
			exists = true
		} else {
			c.DelTable(t)
		}
	}
	if !exists {
		c.AddTable(plan.table)
	}
	if err := plan.reconcileSets(c, exists); err != nil {
		return fmt.Errorf("firewall sets: %w", err)
	}
	if err := plan.reconcileCounters(c, exists); err != nil {
		return fmt.Errorf("firewall counters: %w", err)
	}
	if err := plan.reconcileChains(c, exists); err != nil {
		return fmt.Errorf("firewall chains: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	flushed = true
	if err := c.Flush(); err != nil {
		var errno syscall.Errno
		// Kernel rejections abort the entire batch. Missing ACKs and cancellation
		// remain uncertain and require snapshot recovery instead.
		if ctx.Err() == nil && errors.As(err, &errno) {
			switch errno {
			case syscall.EPERM, syscall.EACCES, syscall.EINVAL, syscall.EEXIST, syscall.ENOENT, syscall.EOPNOTSUPP, syscall.EBUSY, syscall.ENOSPC, syscall.E2BIG, syscall.ERANGE:
				err = errors.Join(errUnchanged, err)
			}
		}
		return fmt.Errorf("atomic firewall apply: %w", err)
	}
	return nil
}
func (nativeBackend) DNS(ctx context.Context, enabled bool) error {
	c, close, err := connection(ctx)
	if err != nil {
		return err
	}
	defer close()
	b := &policyPlan{table: &nftables.Table{Name: "x_node", Family: nftables.TableFamilyINet}, rules: map[string][]*nftables.Rule{}}
	b.redirect(enabled)
	chain := &nftables.Chain{Name: "dns_output", Table: b.table}
	current, err := c.GetRules(b.table, chain)
	if err != nil {
		return err
	}
	if err := reconcileRules(c, current, b.rules["dns_output"]); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.Flush()
}
