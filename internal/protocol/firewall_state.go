package protocol

type FirewallState struct {
	Enabled           bool              `json:"enabled"`
	DetectionEnabled  bool              `json:"detection_enabled"`
	MasterVersion     uint64            `json:"master_version,string"`
	InstanceID        string            `json:"instance_id"`
	SnapshotID        string            `json:"snapshot_id"`
	SourceGenerations map[string]string `json:"source_generations"`
	ErrorCode         string            `json:"error_code,omitempty"`
	KernelReady       bool              `json:"kernel_ready"`
	ActiveBans        int               `json:"active_bans"`
	Sources           int               `json:"sources"`
	SourcePrefixes    int               `json:"source_prefixes"`
	Exemptions        int               `json:"exemptions"`
	PendingReports    int               `json:"pending_reports"`
	Dropped           string            `json:"dropped"`
}
