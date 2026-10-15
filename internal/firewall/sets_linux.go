package firewall

import (
	"bytes"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"go4.org/netipx"
	"net/netip"
	"sort"
)

func (b *policyPlan) staticSets(p protocol.FirewallPolicy, ssh []int) error {
	prefixes := append([]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"}, p.AllowPrefixes...)
	for _, v6 := range []bool{false, true} {
		var builder netipx.IPSetBuilder
		for _, raw := range prefixes {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return err
			}
			if prefix.Addr().Is6() == v6 {
				builder.AddPrefix(prefix.Masked())
			}
		}
		ips, err := builder.IPSet()
		if err != nil {
			return err
		}
		name, key := "lan_v4", nftables.TypeIPAddr
		if v6 {
			name, key = "lan_v6", nftables.TypeIP6Addr
		}
		var elements []nftables.SetElement
		for _, r := range ips.Ranges() {
			end := r.To().Next().AsSlice()
			if end == nil {
				end = make([]byte, key.Bytes)
			}
			elements = append(elements, nftables.SetElement{Key: r.From().AsSlice()}, nftables.SetElement{Key: end, IntervalEnd: true})
		}
		sort.Slice(elements, func(i, j int) bool {
			c := bytes.Compare(elements[i].Key, elements[j].Key)
			return c < 0 || c == 0 && elements[i].IntervalEnd && !elements[j].IntervalEnd
		})
		b.sets = append(b.sets, setSpec{set: &nftables.Set{Table: b.table, Name: name, KeyType: key, Interval: true, AutoMerge: true}, elements: elements})
	}
	tcp := append(append(append([]int(nil), p.TCPPorts...), p.SSHPorts...), ssh...)
	for _, s := range []struct {
		name  string
		ports []int
	}{{"tcp_ports", tcp}, {"udp_ports", p.UDPPorts}} {
		unique := map[int]bool{}
		for _, port := range s.ports {
			unique[port] = true
		}
		ports := make([]int, 0, len(unique))
		for port := range unique {
			ports = append(ports, port)
		}
		sort.Ints(ports)
		var elements []nftables.SetElement
		for _, port := range ports {
			elements = append(elements, nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(uint16(port))})
		}
		b.sets = append(b.sets, setSpec{set: &nftables.Set{Table: b.table, Name: s.name, KeyType: nftables.TypeInetService}, elements: elements})
	}
	return nil
}

func setDelta(current, desired []nftables.SetElement) (add, remove []nftables.SetElement) {
	key := func(e nftables.SetElement) string { return fmt.Sprintf("%x/%t", e.Key, e.IntervalEnd) }
	existing := map[string]nftables.SetElement{}
	for _, e := range current {
		existing[key(e)] = e
	}
	for _, e := range desired {
		if _, ok := existing[key(e)]; !ok {
			add = append(add, e)
		}
		delete(existing, key(e))
	}
	for _, e := range current {
		if _, ok := existing[key(e)]; ok {
			remove = append(remove, e)
		}
	}
	return
}
