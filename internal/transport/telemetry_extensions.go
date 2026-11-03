package transport

import "github.com/VanSail-Opensource/X-Node/internal/protocol"

// Apply the current connection's negotiation at the serialized writer. A queued
// snapshot can outlive a newer-to-older master reconnect.
func (c *Client) telemetryExtensions(message protocol.Message) (protocol.Message, error) {
	if c.ActivityReports() {
		return message, nil
	}
	switch message.Type {
	case "telemetry.report":
		var report protocol.TelemetryReport
		if err := protocol.Decode(message.Data, &report); err != nil {
			return message, err
		}
		report.Users.SampledAt, report.Users.ActiveIPObservations, report.Users.ObservationDrops = nil, nil, 0
		return protocol.New(message.Type, message.ID, message.Revision, report), nil
	case "telemetry.compact":
		var report protocol.CompactTelemetryReport
		if err := protocol.Decode(message.Data, &report); err != nil {
			return message, err
		}
		report.SampledAt, report.ActiveIPObservations, report.ObservationDrops = nil, nil, 0
		return protocol.New(message.Type, message.ID, message.Revision, report), nil
	}
	return message, nil
}
