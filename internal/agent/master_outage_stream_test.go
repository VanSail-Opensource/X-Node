package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/kernel/xray"
)

func TestPaidNativeStreamsSurviveMasterOutageAndRestart(t *testing.T) {
	f := newHourlyAgentFixture(t, false, false)
	first := f.peer(t)
	f.config.Users[0].Hourly = nil
	var native map[string]any
	if err := json.Unmarshal(f.config.Xray, &native); err != nil {
		t.Fatal(err)
	}
	port := int(native["inbounds"].([]any)[0].(map[string]any)["port"].(float64))
	native["outbounds"] = []any{map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.0/8", "::1/128"}}}}}}
	f.config.Xray, _ = json.Marshal(native)
	f.apply(t, first)
	before := f.a.Runtime.Statistics()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer connection.Close(); _, _ = io.Copy(connection, connection) }()
		}
	}()
	outbound := map[string]any{"tag": "peer", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": f.config.Users[0].UUID, "encryption": "none"}}}}}}
	client, closeClient, err := xray.HTTPClient(context.Background(), []any{outbound}, "peer")
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()
	dial := func() net.Conn {
		t.Helper()
		// Xray keeps the direct Dial context for the stream lifetime. Ending a
		// dial-only context here would close the stream before its first write.
		connection, err := client.Transport.(*http.Transport).DialContext(t.Context(), "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal("paid stream admission failed", err)
		}
		return connection
	}
	exchange := func(connection net.Conn, text string) {
		t.Helper()
		// Direct Xray connections do not implement net.Conn deadlines. Closing
		// the pipe bounds each exchange without canceling healthy stream state.
		deadline := time.AfterFunc(3*time.Second, func() { _ = connection.Close() })
		defer deadline.Stop()
		if _, err := connection.Write([]byte(text)); err != nil {
			t.Fatalf("existing paid stream lost its native writer at %s: %v", text, err)
		}
		response := make([]byte, len(text))
		if _, err := io.ReadFull(connection, response); err != nil || !bytes.Equal(response, []byte(text)) {
			t.Fatalf("paid stream stopped forwarding at %s: %v", text, err)
		}
	}
	stream := dial()
	defer stream.Close()
	exchange(stream, "before-outage")
	f.offline.Store(true)
	_ = first.socket.Close()
	await(t, func() bool { return !f.a.Client.Connected() })
	for range 3 {
		exchange(stream, "during-outage")
		<-time.After(450 * time.Millisecond)
	}
	offlineStream := dial()
	defer offlineStream.Close()
	exchange(offlineStream, "admitted-offline")
	f.offline.Store(false)
	second := f.peer(t)
	f.frame(t, second, "state.request", "")
	exchange(stream, "after-master-restart")
	exchange(offlineStream, "offline-stream-after-restart")
	if after := f.a.Runtime.Statistics(); after.NativeBuilds != before.NativeBuilds || after.Rebuilds != before.Rebuilds {
		t.Fatal("master lifecycle unnecessarily rebuilt serving native state", before, after)
	}
}
