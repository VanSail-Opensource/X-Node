package xray

import (
	"context"
	"encoding/json"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	mdns "github.com/miekg/dns"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func TestManagedDNSDoesNotInterceptCoreQueries(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var queries atomic.Int64
			listener, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := &mdns.Server{PacketConn: listener, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) {
				queries.Add(1)
				answer := new(mdns.Msg)
				answer.SetReply(q)
				answer.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: q.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.8")}}
				_ = w.WriteMsg(answer)
			})}
			started := make(chan struct{})
			server.NotifyStartedFunc = func() { close(started) }
			go func() { _ = server.ActivateAndServe() }()
			<-started
			defer server.Shutdown()
			config, port := testConfig(t)
			var root map[string]any
			_ = json.Unmarshal(config.Xray, &root)
			root["dns"] = map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": listener.LocalAddr().(*net.UDPAddr).Port}}, "queryStrategy": "UseIPv4"}
			config.Xray, _ = json.Marshal(root)
			config.DNS.Redirect = true
			registry := sessions.New()
			registry.SetUsers(config.Users)
			runtime := New(registry)
			defer runtime.Stop()
			if err = runtime.Apply(context.Background(), config); err != nil {
				t.Fatal(err)
			}
			if len(runtime.current.Core.Inbound) != 1 {
				t.Fatal("DNS added a host listener")
			}
			peer := map[string]any{"tag": "peer", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": testUUID, "encryption": "none"}}}}}}
			client := nativeClient(t, peer)
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			destination := xnet.TCPDestination(xnet.ParseAddress("8.8.8.8"), 53)
			if network == "udp" {
				destination = xnet.UDPDestination(xnet.ParseAddress("8.8.8.8"), 53)
			}
			conn, err := core.Dial(ctx, client, destination)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
			dnsConn := &mdns.Conn{Conn: conn}
			query := new(mdns.Msg)
			query.SetQuestion("scoped.example.", mdns.TypeA)
			var reply *mdns.Msg
			if network == "udp" {
				raw, e := query.Pack()
				if e != nil {
					t.Fatal(e)
				}
				if _, err = conn.Write(raw); err != nil {
					t.Fatal(err)
				}
				packet := make([]byte, 4096)
				n, e := conn.Read(packet)
				if e != nil {
					t.Fatal(e)
				}
				reply = new(mdns.Msg)
				err = reply.Unpack(packet[:n])
			} else {
				if err = dnsConn.WriteMsg(query); err != nil {
					t.Fatal(err)
				}
				reply, err = dnsConn.ReadMsg()
			}
			if err != nil || reply == nil || len(reply.Answer) != 1 {
				t.Fatalf("DNS response %v %v", reply, err)
			}
			if queries.Load() != 1 {
				t.Fatal("core DNS was redirected recursively", queries.Load())
			}
		})
	}
}
