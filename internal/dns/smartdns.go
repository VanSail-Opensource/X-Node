package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	mdns "github.com/miekg/dns"
)

func SmartConfig(ctx context.Context, p protocol.DNSPolicy) ([]byte, error) {
	var b strings.Builder
	b.WriteString("server-name X-Node\nbind 127.0.0.1:53\nbind [::1]:53\nbind-tcp 127.0.0.1:53\nbind-tcp [::1]:53\ncache-size 8192\n")
	for _, raw := range p.Upstreams {
		u, e := url.Parse(raw)
		if e != nil || u.Scheme != "tls" || u.Hostname() == "" {
			return nil, errors.New("invalid SmartDNS DoT endpoint")
		}
		port := u.Port()
		if port == "" {
			port = "853"
		}
		hostName := u.Hostname()
		if strings.ContainsAny(hostName, "\r\n\t \"'") {
			return nil, errors.New("invalid DoT host")
		}
		ips, e := net.DefaultResolver.LookupIPAddr(ctx, hostName)
		if e != nil || len(ips) == 0 {
			return nil, errors.New("DoT bootstrap resolution failed")
		}
		for _, ip := range ips {
			fmt.Fprintf(&b, "server-tls %s -host-name %s -tls-host-verify %s\n", net.JoinHostPort(ip.IP.String(), port), hostName, hostName)
		}
	}
	return []byte(b.String()), nil
}
func ConfigureSmartDNS(ctx context.Context, p protocol.DNSPolicy, runner host.Runner) error {
	if p.Mode != "smartdns" {
		return nil
	}
	b, err := SmartConfig(ctx, p)
	if err != nil {
		return err
	}
	if _, e := exec.LookPath("smartdns"); e != nil {
		if _, e = runner.Run(ctx, "apt-get", "update"); e != nil {
			return e
		}
		if _, e = runner.Run(ctx, "apt-get", "install", "-y", "smartdns"); e != nil {
			return e
		}
	}
	if err = state.AtomicWrite("/etc/smartdns/smartdns.conf", b, 0600); err != nil {
		return err
	}
	if _, err = runner.Run(ctx, "systemctl", "enable", "--now", "smartdns.service"); err != nil {
		return err
	}
	if _, err = runner.Run(ctx, "systemctl", "restart", "smartdns.service"); err != nil {
		return err
	}
	return ResolverReady(ctx)
}

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
