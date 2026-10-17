package firewall

import (
	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"sync"
	"time"
)

type Pending struct {
	ID                   string                  `json:"id"`
	Deadline             time.Time               `json:"deadline"`
	Status               string                  `json:"status"`
	Unit                 string                  `json:"unit"`
	Candidate            string                  `json:"candidate"`
	Backup               string                  `json:"backup"`
	ConfigPath           string                  `json:"config_path"`
	Policy               protocol.FirewallPolicy `json:"policy"`
	Redirect             bool                    `json:"redirect"`
	SSH                  []int                   `json:"ssh"`
	ForwardIPv4          string                  `json:"forward_ipv4,omitempty"`
	ForwardIPv6          string                  `json:"forward_ipv6,omitempty"`
	ConfigBackup         string                  `json:"config_backup"`
	ConfigExisted        bool                    `json:"config_existed"`
	PolicyBackup         string                  `json:"policy_backup"`
	PolicyExisted        bool                    `json:"policy_existed"`
	ForwardConfigExisted bool                    `json:"forward_config_existed"`
}
type Manager struct {
	banVersion    uint64
	sourceVersion uint64
	mu            sync.Mutex
	Dir           string
	ConfigPath    string
	Executable    string
	Runner        host.Runner
	Backend       Backend
	UnitPath      string
}
