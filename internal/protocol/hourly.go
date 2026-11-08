package protocol

import "time"

const (
	HourlyCapability           = "hourly_account_limits_v1"
	HourlyHeader               = "X-XNode-Hourly"
	HourlyFormat               = "v1"
	HourlySessionHeader        = "X-XNode-Hourly-Session"
	HourlyCreditInstallCommand = "hourly.credit.install"
	HourlyCreditSealCommand    = "hourly.credit.seal"
	HourlyCreditAckCommand     = "hourly.credit.ack"
	MaxHourlyItems             = 128
	MaxHourlyFrameBytes        = 64 << 10
	MaxHourlyBurstBytes        = 16 << 10
	MaxHourlyLifetimeMillis    = 10000
)

type HourlyOwner struct {
	ID         string `json:"id"`
	Generation uint64 `json:"generation,string"`
}

// HourlyUser adds member-ingress enforcement without replacing native accounting.
type HourlyUser struct {
	Owner        HourlyOwner `json:"owner"`
	EnrollmentID string      `json:"enrollment_id"`
}

type HourlyDemand struct {
	Owner          HourlyOwner `json:"owner"`
	Nonce          string      `json:"nonce"`
	LifetimeMillis uint32      `json:"lifetime_ms"`
	PendingBytes   uint64      `json:"pending_bytes,string"`
	MinAtomicBytes uint32      `json:"min_atomic_bytes"`
}

type HourlyDemandBatch struct {
	SessionID string                 `json:"session_id"`
	Demands   []HourlyDemand         `json:"demands"`
	Progress  []HourlyCreditProgress `json:"progress,omitempty"`
}

// Lifetime is measured from the matching demand's original local deadline basis.
// Receipt, retransmission and reconnection cannot extend that deadline.
type HourlyGrant struct {
	SessionID          string      `json:"session_id"`
	Owner              HourlyOwner `json:"owner"`
	Nonce              string      `json:"nonce"`
	Sequence           uint64      `json:"sequence,string"`
	DayUTC             string      `json:"day_utc"`
	LifetimeMillis     uint32      `json:"lifetime_ms"`
	RateBytesPerSecond uint64      `json:"rate_bytes_per_second,string"`
	BurstBytes         uint32      `json:"burst_bytes"`
}

type HourlyGrantAck struct {
	SessionID string      `json:"session_id"`
	Owner     HourlyOwner `json:"owner"`
	Nonce     string      `json:"nonce"`
	Sequence  uint64      `json:"sequence,string"`
	Applied   bool        `json:"applied"`
	Reason    string      `json:"reason,omitempty"`
}

type HourlyGrantAckBatch struct {
	SessionID string           `json:"session_id"`
	Acks      []HourlyGrantAck `json:"acks"`
}

// Samples describe actual admitted payload once, excluding authenticated transit.
type HourlySample struct {
	CounterGeneration uint64      `json:"counter_generation,string"`
	Owner             HourlyOwner `json:"owner"`
	EnrollmentID      string      `json:"enrollment_id"`
	UserID            int         `json:"user_id,string"`
	AccountingPeriod  string      `json:"accounting_period"`
	DayUTC            string      `json:"day_utc"`
	From              time.Time   `json:"from"`
	Through           time.Time   `json:"through"`
	UploadBytes       uint64      `json:"upload_bytes,string"`
	DownloadBytes     uint64      `json:"download_bytes,string"`
}
