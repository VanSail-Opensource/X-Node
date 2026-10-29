package transport

import (
	"encoding/json"
	"strings"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/gorilla/websocket"
)

func (c *Client) writeMessage(socket *websocket.Conn, message protocol.Message) error {
	if strings.HasPrefix(message.Type, "compute.") && !c.ComputePool() {
		return nil
	}
	// A reconnect to a legacy master must not send a queued extension frame.
	// Its durable event remains pending until a capable master acknowledges it.
	if message.Type == "ddns.changes" && !c.DDNSChanges() {
		return nil
	}
	// A snapshot queued by an earlier connection can outlive negotiation. Always
	// fall back before writing it to a legacy master, including reconnect races.
	if message.Type == "telemetry.compact" && !c.CompactTelemetry() {
		var compact protocol.CompactTelemetryReport
		if err := protocol.Decode(message.Data, &compact); err != nil {
			return err
		}
		report, err := protocol.ExpandTelemetry(compact)
		if err != nil {
			return err
		}
		message = protocol.New("telemetry.report", message.ID, message.Revision, report)
	}
	// Strict older masters must never receive the extension, even from a snapshot
	// queued before reconnect. Strip it at the connection's serialized writer.
	if !c.OpenConnections() {
		switch message.Type {
		case "telemetry.report":
			var report protocol.TelemetryReport
			if err := protocol.Decode(message.Data, &report); err != nil {
				return err
			}
			report.Users.TotalConnections = nil
			message = protocol.New(message.Type, message.ID, message.Revision, report)
		case "telemetry.compact":
			var report protocol.CompactTelemetryReport
			if err := protocol.Decode(message.Data, &report); err != nil {
				return err
			}
			for index := range report.Users {
				report.Users[index].TotalConnections = 0
			}
			message = protocol.New(message.Type, message.ID, message.Revision, report)
		}
	}
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	if len(data) > protocol.MaxFrameBytes {
		return websocket.ErrReadLimit
	}
	report := message.Type == "telemetry.report" || message.Type == "telemetry.compact" || message.Type == "traffic.report" || message.Type == "logs.report"
	socket.EnableWriteCompression(report && len(message.Data) >= 1024)
	return socket.WriteMessage(websocket.TextMessage, data)
}
