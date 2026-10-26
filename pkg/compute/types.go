// Package compute implements bounded, deterministic numerical kernels. It has
// no network, credentials, database, wallet, or authorization dependencies.
package compute

import "encoding/json"

const Version = "pricing-kernels-v1"
const MaxItems = 64
const MaxInputBytes = 256 << 10
const MaxResultBytes = 4 << 20
const MaxCompressedBytes = 1 << 20
const ChunkBytes = 64 << 10

type Task struct {
	ID           string                `json:"id"`
	Kind         string                `json:"kind"`
	Samples      []float64             `json:"samples,omitempty"`
	Observations []ResponseObservation `json:"observations,omitempty"`
	Model        ResponseModel         `json:"model"`
	Candidates   []CandidateInput      `json:"candidates,omitempty"`
}

type Batch struct {
	Version string `json:"version"`
	Tasks   []Task `json:"tasks"`
}

type Quantiles struct {
	P10  float64 `json:"p10"`
	P50  float64 `json:"p50"`
	P90  float64 `json:"p90"`
	Mean float64 `json:"mean"`
}

type CandidateInput struct {
	Price    int64               `json:"priceMinor,string"`
	NetPrice int64               `json:"netPriceMinor,string"`
	Units    float64             `json:"units"`
	Cost     float64             `json:"cost"`
	Features ResponseObservation `json:"features"`
}

type Candidate struct {
	Price        int64   `json:"priceMinor,string"`
	Probability  float64 `json:"probability"`
	Revenue      float64 `json:"revenueMinor"`
	Contribution float64 `json:"contributionMinor"`
}

type Result struct {
	ID         string         `json:"id"`
	Kind       string         `json:"kind"`
	Quantiles  *Quantiles     `json:"quantiles,omitempty"`
	Model      *ResponseModel `json:"model,omitempty"`
	Candidates []Candidate    `json:"candidates,omitempty"`
}

type Results struct {
	Version   string   `json:"version"`
	InputHash string   `json:"inputHash"`
	Items     []Result `json:"items"`
}

func DigestBatch(b Batch) (json.RawMessage, string, error) {
	raw, err := json.Marshal(b)
	return raw, Digest(raw), err
}
