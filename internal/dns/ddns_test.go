package dns

import (
	"context"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/libdns/libdns"
	"testing"
)

type setter struct {
	records []libdns.Record
	zone    string
}

func (s *setter) SetRecords(_ context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	s.zone = zone
	s.records = records
	return records, nil
}
func TestDDNSOwnsOnlyNamedAddressRecords(t *testing.T) {
	s := &setter{}
	j := protocol.DDNSJob{ID: "home", Zone: "example.com", Name: "node.example.com", IPv4: "192.0.2.1", IPv6: "2001:db8::1"}
	r, e := DDNS(context.Background(), j, s, nil)
	if e != nil {
		t.Fatal(e)
	}
	if len(s.records) != 2 || s.zone != "example.com." || r.IPv4 != "192.0.2.1" {
		t.Fatal("wrong update")
	}
	for _, record := range s.records {
		rr := record.RR()
		if rr.Name != "node" || rr.Type != "A" && rr.Type != "AAAA" {
			t.Fatal("unrelated RRset modified")
		}
	}
	j.Name = "outside.invalid"
	if _, e = DDNS(context.Background(), j, s, nil); e == nil {
		t.Fatal("outside zone accepted")
	}
}
