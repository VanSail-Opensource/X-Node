package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/kernel/xray"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestAgentGracefulShutdownSealsRealHourlyStreamBeforeClosingJournal(t *testing.T) {
	f := newHourlyAgentFixture(t, true, false)
	peer := f.peer(t)
	var native map[string]any
	if err := json.Unmarshal(f.config.Xray, &native); err != nil {
		t.Fatal(err)
	}
	port := int(native["inbounds"].([]any)[0].(map[string]any)["port"].(float64))
	native["outbounds"] = []any{map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.0/8", "::1/128"}}}}}}
	f.config.Xray, _ = json.Marshal(native)
	f.apply(t, peer)
	installs := []protocol.HourlyCreditInstall{f.install(peer, "free-credit", 1), f.install(peer, "extra-credit", 2)}
	installs[1].Kind, installs[1].ByteCeiling = "extra", 2000
	for _, install := range installs {
		if result := f.command(t, peer, "install-"+install.ReservationID, protocol.HourlyCreditInstallCommand, install); result.Status != "completed" {
			t.Fatal(result.Status, result.Error)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = io.Copy(connection, connection)
	}()
	outbound := map[string]any{"tag": "peer", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": f.config.Users[0].UUID, "encryption": "none"}}}}}}
	client, closeClient, err := xray.HTTPClient(context.Background(), []any{outbound}, "peer")
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()
	stream, err := client.Transport.(*http.Transport).DialContext(t.Context(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	payload := []byte("planned-restart-payload")
	// Direct Xray streams do not implement deadlines. Bound only this exchange;
	// leave the live stream open for the actual Agent.Run cancellation below.
	deadline := time.AfterFunc(3*time.Second, func() { _ = stream.Close() })
	defer deadline.Stop()
	if _, err = stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(stream, response); err != nil || !bytes.Equal(response, payload) {
		t.Fatal("hourly native stream did not echo admitted payload", err)
	}
	deadline.Stop()
	admitted := uint64(len(payload))
	await(t, func() bool {
		for _, progress := range f.a.hourly.controller.CreditProgress(protocol.MaxHourlyItems) {
			if progress.ReservationID == installs[0].ReservationID {
				return progress.AdmittedUploadBytes == admitted && progress.AdmittedDownloadBytes == admitted
			}
		}
		return false
	})
	// This is the process's cancelled context, not a test-only call to the seal
	// helper. Cleanup must use a fresh context and precede runtime teardown.
	f.cancel()
	await(t, func() bool { return !f.a.Runtime.Ready() && !f.a.hourly.store.Healthy() })
	reopened, err := hourly.OpenCreditStore(filepath.Join(f.a.Dir, "hourly-credits.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	proofs := reopened.Recovery()
	if len(proofs) != len(installs) {
		t.Fatal("planned restart lost hourly obligations", proofs)
	}
	for i, proof := range proofs {
		used := uint64(0)
		if i == 0 {
			used = admitted
		}
		if proof.Install != installs[i] || proof.AdmittedUploadBytes != used || proof.AdmittedDownloadBytes != used || proof.UnusedBytes != installs[i].ByteCeiling-2*used || proof.UnknownBytes != 0 || proof.Recovery || protocol.ValidateHourlyProof(proof) != nil {
			t.Fatal("planned restart changed exact original admission evidence", proof)
		}
		if _, err = reopened.Install(context.Background(), installs[i]); err == nil {
			t.Fatal("sealed old-boot reservation became spendable on restart")
		}
	}
}
