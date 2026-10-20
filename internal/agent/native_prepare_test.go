package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/cert"
	"github.com/VanSail-Opensource/X-Node/internal/geodata"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	coredata "github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"
)

func TestNativePreparationResolvesGeositeBeforeValidation(t *testing.T) {
	dir := t.TempDir()
	assets := filepath.Join(dir, "geodata")
	if err := os.MkdirAll(assets, 0700); err != nil {
		t.Fatal(err)
	}
	raw, err := proto.Marshal(&coredata.GeoSiteList{Entry: []*coredata.GeoSite{{Code: "GOOGLE", Domain: []*coredata.Domain{{Type: coredata.Domain_Full, Value: "google.com"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(assets, "geosite.dat"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	a := &Agent{Dir: dir, Certificates: cert.NewPool(filepath.Join(dir, "certs"))}
	defer a.Certificates.Stop()
	c := protocol.Config{Xray: json.RawMessage(`{"inbounds":[],"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","domain":["geosite:google"],"outboundTag":"direct"}]}}`)}
	if _, _, err = a.prepareNative(context.Background(), context.Background(), c, geodata.Policy{}); err != nil {
		t.Fatal(err)
	}
}

func TestValidationProofUsesContentAndNeverSeedsActivation(t *testing.T) {
	dir := t.TempDir()
	assets := filepath.Join(dir, "geodata")
	if err := os.MkdirAll(assets, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(domain string) {
		t.Helper()
		raw, err := proto.Marshal(&coredata.GeoSiteList{Entry: []*coredata.GeoSite{{Code: "GOOGLE", Domain: []*coredata.Domain{{Type: coredata.Domain_Full, Value: domain}}}}})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(assets, "geosite.dat"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("google.com")
	a := &Agent{Dir: dir, Certificates: cert.NewPool(filepath.Join(dir, "certs"))}
	defer a.Certificates.Stop()
	c := protocol.Config{Xray: json.RawMessage(`{"inbounds":[],"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","domain":["geosite:google"],"outboundTag":"direct"}]}}`), Users: []protocol.User{}}
	if err := a.validateNative(context.Background(), c, geodata.Policy{}); err != nil {
		t.Fatal(err)
	}
	if !a.validationValid || a.nativePrepared != nil {
		t.Fatal("validation material escaped into activation")
	}
	key := a.validationKey
	write("google.net")
	stamp := time.Unix(1000, 0)
	if err := os.Chtimes(filepath.Join(assets, "geosite.dat"), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	next, err := a.validationIdentity(c, geodata.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if next == key {
		t.Fatal("content change reused proof")
	}
	if err = a.validateNative(context.Background(), c, geodata.Policy{}); err != nil {
		t.Fatal(err)
	}
	if a.validationKey == key || a.nativePrepared != nil {
		t.Fatal("changed proof or synthetic isolation lost")
	}
}
