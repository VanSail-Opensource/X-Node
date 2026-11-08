package hourly

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Hash the canonical typed document without its own checksum. This detects
// omission of otherwise valid individual records as well as field corruption.
func creditJournalDigest(journal creditJournal) string {
	journal.Digest = ""
	raw, _ := json.Marshal(journal)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
