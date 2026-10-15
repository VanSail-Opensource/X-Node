package main

import (
	"context"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/dns"
	"github.com/VanSail-Opensource/X-Node/internal/firewall"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	mdns "github.com/miekg/dns"
	"net"
	"time"
)

func dnsChecks(ctx context.Context, m *firewall.Manager, p protocol.FirewallPolicy) error {
	if dns.ResolverReady(ctx) == nil {
		return fmt.Errorf("unexpected resolver already occupies fixture loopback")
	}
	var servers []*mdns.Server
	defer func() {
		for _, s := range servers {
			_ = s.Shutdown()
		}
	}()
	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) {
		reply := new(mdns.Msg)
		reply.SetReply(q)
		_ = w.WriteMsg(reply)
	})
	for _, address := range []string{"127.0.0.1:53", "[::1]:53"} {
		for _, network := range []string{"tcp", "udp"} {
			s := &mdns.Server{Handler: handler}
			var err error
			if network == "tcp" {
				s.Listener, err = net.Listen(network, address)
			} else {
				s.PacketConn, err = net.ListenPacket(network, address)
			}
			if err != nil {
				return err
			}
			started := make(chan struct{})
			s.NotifyStartedFunc = func() { close(started) }
			servers = append(servers, s)
			failures := make(chan error, 1)
			go func() { failures <- s.ActivateAndServe() }()
			select {
			case <-started:
			case err := <-failures:
				return err
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if err := dns.ResolverReady(ctx); err != nil {
		return err
	}
	tx, err := m.Apply(ctx, "fixture-dns", p, true)
	if err != nil {
		return err
	}
	if err = m.Confirm(ctx, tx.ID); err != nil {
		return err
	}
	for _, address := range []string{"198.18.0.6:53", "[2001:db8:2::2]:53"} {
		for _, network := range []string{"tcp", "udp"} {
			question := new(mdns.Msg)
			question.SetQuestion("localhost.", mdns.TypeA)
			c := &mdns.Client{Net: network, Timeout: 2 * time.Second}
			reply, _, err := c.ExchangeContext(ctx, question, address)
			if err != nil || reply == nil || reply.Id != question.Id {
				return fmt.Errorf("%s DNS redirect %s failed: %w", network, address, err)
			}
		}
	}
	return m.EnableConfirmedDNS(ctx, false)
}
