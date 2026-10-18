package firewall

import "github.com/VanSail-Opensource/X-Node/internal/protocol"

func (g *Guard) rebuildExemptionMasks() {
	g.exemptionMasks = map[int]bool{}
	for raw := range g.state.Exemptions {
		if p, err := protocol.ExemptionPrefix(raw); err == nil && p.Bits() != p.Addr().BitLen() {
			bits := p.Bits()
			if p.Addr().Is6() {
				bits += 256
			}
			g.exemptionMasks[bits] = true
		}
	}
}
