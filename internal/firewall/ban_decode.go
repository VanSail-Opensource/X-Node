package firewall

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Decode through the same bound until EOF, including gzip footer verification.
// Missing snapshot fields must not inherit the freshly generated empty state.
func (g *Guard) decodeBanSnapshot(input io.Reader, limit int64) error {
	g.state = banState{}
	bounded := &io.LimitedReader{R: input, N: limit + 1}
	decoder := json.NewDecoder(bounded)
	if err := g.decodeBanState(decoder); err != nil {
		return err
	}
	var extra any
	err := decoder.Decode(&extra)
	if bounded.N == 0 {
		return errors.New("firewall checkpoint exceeds limit")
	}
	if err != io.EOF {
		if err != nil {
			return err
		}
		return errors.New("firewall checkpoint contains trailing data")
	}
	if g.state.Bans == nil || g.state.Exemptions == nil || g.state.Sources == nil || g.state.Events == nil || !protocol.ValidName(g.state.EventNamespace) || !protocol.ValidName(g.state.JournalEpoch) {
		return errors.New("invalid persisted firewall state")
	}
	return nil
}
