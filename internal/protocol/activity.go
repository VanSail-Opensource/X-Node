package protocol

import "time"

const ActivityObservationsCapability = "activity_observations_v1"
const ActivityObservationsHeader = "X-XNode-Activity"
const ActivityObservationsFormat = "observations-v1"
const MaxActivityObservations = 16384

// IPActivity records a sampled payload observation. It is boot-scoped volatile
// evidence, independent of the report envelope's publication time.
type IPActivity struct {
	UserID       int       `json:"user_id"`
	IP           string    `json:"ip"`
	LastActive   time.Time `json:"last_active"`
	Observations uint64    `json:"observations,string"`
}
