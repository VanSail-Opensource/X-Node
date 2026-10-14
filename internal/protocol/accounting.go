package protocol

import "time"

// Traffic contains raw uploaded and downloaded payload bytes, in that order.
type Traffic map[int][2]uint64

// TrafficSample remains bound to its authorization accounting period across replay.
type TrafficSample struct {
	UserID           int       `json:"user_id"`
	AccountingPeriod string    `json:"accounting_period"`
	From             time.Time `json:"from"`
	Through          time.Time `json:"through"`
	UploadBytes      uint64    `json:"upload_bytes"`
	DownloadBytes    uint64    `json:"download_bytes"`
}

// TrafficReport is an immutable journal batch. Samples replace legacy totals for billing.
type TrafficReport struct {
	ID      string          `json:"id"`
	Traffic Traffic         `json:"traffic"`
	Samples []TrafficSample `json:"samples,omitempty"`
}

// UserRate is measured payload throughput; it is independent of configured speed caps.
type UserRate struct {
	UploadBytesPerSecond   float64 `json:"upload_bytes_per_second"`
	DownloadBytesPerSecond float64 `json:"download_bytes_per_second"`
	SampleSeconds          float64 `json:"sample_seconds"`
}

type TrafficFlush struct {
	UserID           int    `json:"user_id,omitempty"`
	Quiesce          bool   `json:"quiesce,omitempty"`
	AccountingPeriod string `json:"accounting_period,omitempty"`
}

// TrafficBarrier identifies the journal sequence covering a serialized capture.
type TrafficBarrier struct {
	AgentID          string    `json:"agent_id"`
	Sequence         uint64    `json:"sequence"`
	Through          time.Time `json:"through"`
	Quiesced         bool      `json:"quiesced"`
	AccountingPeriod string    `json:"accounting_period,omitempty"`
}
