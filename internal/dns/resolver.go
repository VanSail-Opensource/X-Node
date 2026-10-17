package dns

import (
	"context"
	"errors"
	mdns "github.com/miekg/dns"
	"time"
)

// ResolverReady probes actual DNS replies over TCP and UDP on both loopback families.
func ResolverReady(ctx context.Context) error {
	for _, address := range []string{"127.0.0.1:53", "[::1]:53"} {
		for _, network := range []string{"udp", "tcp"} {
			m := new(mdns.Msg)
			m.SetQuestion("localhost.", mdns.TypeA)
			client := &mdns.Client{Net: network, Timeout: 2 * time.Second}
			reply, _, err := client.ExchangeContext(ctx, m, address)
			if err != nil || reply == nil || reply.Id != m.Id {
				return errors.New("loopback DNS TCP/UDP listener is not ready")
			}
		}
	}
	return nil
}
