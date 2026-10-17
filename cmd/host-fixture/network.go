package main

import (
	"bufio"
	"context"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"os/exec"
	"time"
)

func topology(ctx context.Context, r host.Runner) error {
	for _, side := range []struct{ name, host4, peer4, host6, peer6 string }{
		{"client", "198.18.0.1/30", "198.18.0.2/30", "2001:db8:1::1/64", "2001:db8:1::2/64"},
		{"target", "198.18.0.5/30", "198.18.0.6/30", "2001:db8:2::1/64", "2001:db8:2::2/64"},
	} {
		ns := "xnode-" + side.name
		link := "xn-" + side.name
		commands := [][]string{
			{"netns", "add", ns}, {"link", "add", link, "type", "veth", "peer", "name", "peer"},
			{"link", "set", "peer", "netns", ns}, {"addr", "add", side.host4, "dev", link}, {"-6", "addr", "add", side.host6, "dev", link, "nodad"}, {"link", "set", link, "up"},
			{"-n", ns, "link", "set", "lo", "up"}, {"-n", ns, "addr", "add", side.peer4, "dev", "peer"}, {"-n", ns, "-6", "addr", "add", side.peer6, "dev", "peer", "nodad"}, {"-n", ns, "link", "set", "peer", "up"},
		}
		for _, args := range commands {
			if _, err := r.Run(ctx, "ip", args...); err != nil {
				return fmt.Errorf("topology %v: %w", args, err)
			}
		}
	}
	for _, args := range [][]string{{"-n", "xnode-client", "route", "add", "default", "via", "198.18.0.1"}, {"-n", "xnode-client", "-6", "route", "add", "default", "via", "2001:db8:1::1"}, {"-n", "xnode-target", "route", "add", "default", "via", "198.18.0.5"}, {"-n", "xnode-target", "-6", "route", "add", "default", "via", "2001:db8:2::1"}} {
		if _, err := r.Run(ctx, "ip", args...); err != nil {
			return err
		}
	}
	return nil
}
func forwardingPolicy() []protocol.Forward {
	var result []protocol.Forward
	for _, network := range []string{"tcp", "udp"} {
		result = append(result, protocol.Forward{ListenIP: "198.18.0.1", Port: 24443, TargetIP: "198.18.0.6", TargetPort: 9000, Network: network}, protocol.Forward{ListenIP: "2001:db8:1::1", Port: 24443, TargetIP: "2001:db8:2::2", TargetPort: 9000, Network: network})
	}
	return result
}

const echoServer = `import socket,threading,sys
def serve(family,kind,address,port):
 s=socket.socket(family,kind)
 s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 if family==socket.AF_INET6: s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind((address,port))
 if kind==socket.SOCK_STREAM: s.listen()
 def run():
  if kind==socket.SOCK_STREAM:
   while True:
    c,_=s.accept()
    with c: c.sendall(c.recv(1024))
  else:
   while True:
    data,peer=s.recvfrom(1024);s.sendto(data,peer)
 threading.Thread(target=run,daemon=True).start()
for family,address in [(socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')]:
 for kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]: serve(family,kind,address,int(sys.argv[1]))
print('ready',flush=True)
threading.Event().wait()
`

func startEcho(ctx context.Context, namespace string, port string) (func(), error) {
	args := []string{"-u", "-c", echoServer, port}
	name := "python3"
	if namespace != "" {
		name = "ip"
		args = append([]string{"netns", "exec", namespace, "python3"}, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	stop := func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }
	ready := make(chan bool, 1)
	go func() { scanner := bufio.NewScanner(out); ready <- scanner.Scan() && scanner.Text() == "ready" }()
	select {
	case ok := <-ready:
		if !ok {
			stop()
			return nil, fmt.Errorf("echo server failed")
		}
		return stop, nil
	case <-ctx.Done():
		stop()
		return nil, ctx.Err()
	case <-time.After(5 * time.Second):
		stop()
		return nil, fmt.Errorf("echo server readiness timeout")
	}
}

const echoProbe = `import socket,sys
family=socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET
kind=socket.SOCK_STREAM if sys.argv[3]=='tcp' else socket.SOCK_DGRAM
s=socket.socket(family,kind);s.settimeout(2)
if len(sys.argv)>4: s.bind((sys.argv[4],0))
s.connect((sys.argv[1],int(sys.argv[2])));s.sendall(b'x-node-fixture')
assert s.recv(128)==b'x-node-fixture'
`

func packetChecks(ctx context.Context, r host.Runner) error {
	stop, err := startEcho(ctx, "", "9443")
	if err != nil {
		return err
	}
	defer stop()
	stopTarget, err := startEcho(ctx, "xnode-target", "9000")
	if err != nil {
		return err
	}
	defer stopTarget()
	for _, addr := range []string{"198.18.0.1", "2001:db8:1::1"} {
		for _, port := range []string{"9443", "24443"} {
			for _, network := range []string{"tcp", "udp"} {
				if _, err := r.Run(ctx, "ip", "netns", "exec", "xnode-client", "python3", "-c", echoProbe, addr, port, network); err != nil {
					return fmt.Errorf("%s %s:%s: %w", network, addr, port, err)
				}
			}
		}
	}
	// A listening but closed service must time out, rather than receive a reply.
	stopClosed, err := startEcho(ctx, "", "9444")
	if err != nil {
		return err
	}
	defer stopClosed()
	if _, err := r.Run(ctx, "ip", "netns", "exec", "xnode-client", "python3", "-c", echoProbe, "198.18.0.1", "9444", "tcp"); err == nil {
		return fmt.Errorf("closed TCP port was reachable")
	}
	return nil
}
