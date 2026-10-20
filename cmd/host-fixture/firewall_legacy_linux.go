package main

import (
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"time"
)

// Called exclusively inside the disposable host before policy reconciliation.
func legacyBanFixture(c *nftables.Conn, table *nftables.Table) error {
	chain := c.AddChain(&nftables.Chain{Table: table, Name: "fixture_legacy_bans"})
	for _, v6 := range []bool{false, true} {
		name, key, size := "banned_v4", nftables.TypeIPAddr, 4
		if v6 {
			name, key, size = "banned_v6_64", nftables.TypeIP6Addr, 16
		}
		set := &nftables.Set{Table: table, Name: name, KeyType: key, Dynamic: true, HasTimeout: true, Timeout: 72 * time.Hour, Size: 65535}
		if err := c.AddSet(set, nil); err != nil {
			return err
		}
		c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{&expr.Immediate{Register: 1, Data: make([]byte, size)}, &expr.Lookup{SourceRegister: 1, SetName: name, SetID: set.ID}}})
	}
	return c.Flush()
}
