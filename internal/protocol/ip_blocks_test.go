package protocol

import (
	"reflect"
	"testing"
	"time"
)

func TestRemapIPBlocksPreservesScopeAndLatestExpiry(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	for _, targetLater := range []bool{false, true} {
		t.Run(map[bool]string{false: "source later", true: "target later"}[targetLater], func(t *testing.T) {
			old := IPBlock{SourceIP: "192.0.2.1", UserID: 10, Until: now.Add(10 * time.Minute)}
			target := old
			target.UserID, target.Until = 20, now.Add(time.Minute)
			if targetLater {
				target.Until = now.Add(time.Hour)
			}
			global, unrelated := old, old
			global.UserID, unrelated.UserID = 0, 30
			ipv6 := IPBlock{SourceIP: "2001:db8::1", UserID: 10, Until: old.Until}
			blocks := map[string]IPBlock{
				IPBlockKey(10, old.SourceIP): old, IPBlockKey(20, target.SourceIP): target,
				IPBlockKey(0, old.SourceIP): global, IPBlockKey(30, old.SourceIP): unrelated,
				IPBlockKey(10, ipv6.SourceIP): ipv6, "mismatched-key": old,
			}
			before := Clone(blocks)
			mapping := map[int]int{10: 20}
			next := RemapIPBlocks(blocks, mapping)
			if _, exists := next[IPBlockKey(10, old.SourceIP)]; exists {
				t.Fatal("old scoped restriction remained under its numeric predecessor")
			}
			want := old.Until
			if targetLater {
				want = target.Until
			}
			merged := next[IPBlockKey(20, old.SourceIP)]
			if merged.UserID != 20 || merged.SourceIP != old.SourceIP || !merged.Until.Equal(want) {
				t.Fatal("replacement weakened or changed scoped restriction", merged)
			}
			if !reflect.DeepEqual(next[IPBlockKey(0, old.SourceIP)], global) || !reflect.DeepEqual(next[IPBlockKey(30, old.SourceIP)], unrelated) || !reflect.DeepEqual(next["mismatched-key"], old) {
				t.Fatal("global, unrelated or mismatched-key restriction changed")
			}
			if moved := next[IPBlockKey(20, ipv6.SourceIP)]; moved.UserID != 20 || !moved.Until.Equal(ipv6.Until) {
				t.Fatal("exact IPv6 restriction was not preserved")
			}
			if !reflect.DeepEqual(blocks, before) || mapping[10] != 20 {
				t.Fatal("restriction remapping mutated input snapshots")
			}
			delete(next, IPBlockKey(0, old.SourceIP))
			if !reflect.DeepEqual(blocks, before) {
				t.Fatal("returned restriction map aliases caller storage")
			}
		})
	}
}

func TestRemapIPBlocksReadsOriginalSubjectsWithoutCascading(t *testing.T) {
	first := IPBlock{SourceIP: "192.0.2.1", UserID: 1, Until: time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)}
	second := first
	second.UserID, second.Until = 2, first.Until.Add(time.Hour)
	blocks := map[string]IPBlock{IPBlockKey(1, first.SourceIP): first, IPBlockKey(2, first.SourceIP): second}
	next := RemapIPBlocks(blocks, map[int]int{1: 2, 2: 3})
	if len(next) != 2 || !next[IPBlockKey(2, first.SourceIP)].Until.Equal(first.Until) || !next[IPBlockKey(3, first.SourceIP)].Until.Equal(second.Until) {
		t.Fatal("an incoming restriction cascaded through another original subject", next)
	}
	if next[IPBlockKey(2, first.SourceIP)].UserID != 2 || next[IPBlockKey(3, first.SourceIP)].UserID != 3 {
		t.Fatal("scoped record body did not follow its new exact key")
	}
}

func TestRemapIPBlocksNeverWidensInvalidOrGlobalScopes(t *testing.T) {
	block := IPBlock{SourceIP: "192.0.2.1", UserID: 1, Until: time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)}
	global := block
	global.UserID = 0
	blocks := map[string]IPBlock{IPBlockKey(1, block.SourceIP): block, IPBlockKey(0, block.SourceIP): global}
	for _, mapping := range []map[int]int{nil, {1: 0}, {1: -1}, {1: 1}, {0: 5}} {
		if next := RemapIPBlocks(blocks, mapping); !reflect.DeepEqual(next, blocks) {
			t.Fatal("invalid scope mapping changed user or global restrictions", next)
		}
	}
	if next := RemapIPBlocks(nil, map[int]int{1: 2}); next != nil {
		t.Fatal("nil restrictions acquired a fabricated record")
	}
}
