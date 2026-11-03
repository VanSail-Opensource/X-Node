package protocol

import wire "github.com/VanSail-Opensource/X-Node/internal/protocol"

const TrafficStreamCapability = wire.TrafficStreamCapability
const TrafficStreamHeader = wire.TrafficStreamHeader
const TrafficStreamFormat = wire.TrafficStreamFormat

func TrafficSequence(agent string, report TrafficReport) (uint64, error) {
	return wire.TrafficSequence(agent, report)
}

func ValidStreamID(value string) bool { return wire.ValidStreamID(value) }
