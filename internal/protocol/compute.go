package protocol

import "encoding/json"

const ComputePoolCapability = "compute_pool_v1"
const ComputePoolHeader = "X-Xnode-Compute-Pool"
const ComputePoolFormat = "v1"

type ComputeSignal struct {
	BatchID   string `json:"batch_id"`
	Attempt   int    `json:"attempt"`
	InputHash string `json:"input_hash"`
}

type ComputeAnnouncement struct {
	Signal   ComputeSignal `json:"signal"`
	Version  string        `json:"version"`
	Items    int           `json:"items"`
	Bytes    int           `json:"bytes"`
	Deadline int64         `json:"deadline"`
}

type ComputeGrant struct {
	Offer ComputeAnnouncement `json:"offer"`
	Input json.RawMessage     `json:"input"`
}

type ComputeChunk struct {
	Signal     ComputeSignal `json:"signal"`
	ResultHash string        `json:"result_hash"`
	Index      int           `json:"index"`
	Total      int           `json:"total"`
	Data       string        `json:"data"`
}
