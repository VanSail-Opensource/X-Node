package protocol

import (
	"fmt"
	"maps"
)

// IPBlockKey binds one exact source address to its numeric subject; user zero
// remains the independently configured global scope.
func IPBlockKey(user int, ip string) string { return fmt.Sprintf("%d:%s", user, ip) }

// RemapIPBlocks returns a fresh map using an already validated replacement map.
// Both passes read the original blocks: a destination that was another source
// cannot accidentally cascade a restriction through multiple numeric subjects.
// Mismatched keys and invalid replacement scopes remain untouched.
func RemapIPBlocks(blocks map[string]IPBlock, replacements map[int]int) map[string]IPBlock {
	next := maps.Clone(blocks)
	for key, block := range blocks {
		if _, moving := blockReplacement(key, block, replacements); moving {
			delete(next, key)
		}
	}
	for key, block := range blocks {
		target, moving := blockReplacement(key, block, replacements)
		if !moving {
			continue
		}
		block.UserID = target
		targetKey := IPBlockKey(target, block.SourceIP)
		if current, exists := next[targetKey]; !exists || block.Until.After(current.Until) {
			next[targetKey] = block
		}
	}
	return next
}

func blockReplacement(key string, block IPBlock, replacements map[int]int) (int, bool) {
	target, exists := replacements[block.UserID]
	return target, exists && block.UserID > 0 && target > 0 && target != block.UserID &&
		key == IPBlockKey(block.UserID, block.SourceIP)
}
