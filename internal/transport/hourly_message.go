package transport

import (
	"encoding/json"
	"strings"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (c *Client) hourlyMessage(message protocol.Message) (protocol.Message, bool, error) {
	if strings.HasPrefix(message.Type, "hourly.") {
		if !c.Hourly() {
			return message, false, nil
		}
		if message.Type != "hourly.credit.proofs" {
			var binding struct {
				SessionID string `json:"session_id"`
			}
			if err := json.Unmarshal(message.Data, &binding); err != nil {
				return message, false, err
			}
			if binding.SessionID != c.HourlySession() {
				return message, false, nil
			}
		}
	}
	if message.Type == "traffic.report" && !c.Hourly() {
		var report protocol.TrafficReport
		if err := protocol.Decode(message.Data, &report); err != nil {
			return message, false, err
		}
		if len(report.HourlySamples) > 0 || report.DroppedHourlySamples > 0 {
			return message, false, nil // Preserve the complete immutable journal.
		}
	}
	return message, true, nil
}
