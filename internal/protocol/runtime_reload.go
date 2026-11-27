package protocol

// RuntimeReloadArgs rechecks external material and applies it live where possible.
// Changed active receivers may require an embedded restart. Force is accepted
// for compatibility and does not restart an unchanged runtime.
type RuntimeReloadArgs struct {
	Force bool `json:"force,omitempty"`
}
