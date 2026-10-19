package protocol

// GeoIPPrefixesPerChunk bounds each master-to-agent country transfer frame.
const GeoIPPrefixesPerChunk = 256

// GeoIPChunk stages master-resolved country ranges independently of config frames.
// Probe only checks an immutable generation and never advances its chunk cursor.
type GeoIPChunk struct {
	Generation string   `json:"generation"`
	Probe      bool     `json:"probe,omitempty"`
	Index      int      `json:"index,omitempty"`
	Final      bool     `json:"final,omitempty"`
	Prefixes   []string `json:"prefixes,omitempty"`
}
