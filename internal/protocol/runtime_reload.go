package protocol

// RuntimeReloadArgs rechecks external material and applies it incrementally.
// Force is accepted from older masters but no longer restarts a serving core.
type RuntimeReloadArgs struct {
	Force bool `json:"force,omitempty"`
}
