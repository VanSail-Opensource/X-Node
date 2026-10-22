package protocol

// RuntimeReloadArgs rechecks external material and uses incremental application
// by default. Force explicitly requests full recovery reconstruction.
type RuntimeReloadArgs struct {
	Force bool `json:"force,omitempty"`
}
