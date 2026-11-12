package sessions

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type Connection struct {
	ID              string    `json:"id"`
	UserID          int       `json:"user_id"`
	InboundTag      string    `json:"inbound_tag"`
	SourceIP        string    `json:"source_ip"`
	Destination     string    `json:"destination"`
	DestinationPort int       `json:"destination_port"`
	Network         string    `json:"network"`
	Started         time.Time `json:"started"`
}
type userState struct {
	policy           protocol.User
	identities       identityIndex
	ips              map[string]int
	count            int
	clients          int
	handlers         int
	speed            *speedPolicy
	upload, download atomic.Uint64
}
type Registry struct {
	mu                    sync.RWMutex
	prefix                string
	sequence              uint64
	users                 map[int]*userState
	identityAliases       map[int]int
	authorizationSequence uint64
	authorizationRevision uint64
	connections           map[string]*Lease
	bans                  map[int]time.Time
	ports                 []protocol.PortRange
	rejects               map[string]uint64
	paused                bool
	epochs                map[string]string
	OnBan                 func(int, time.Time)
	OnReject              func(AdmissionEvent)
	ipBlocks              map[string]protocol.IPBlock
	accounting            map[accountingKey]*accountingCounters
	inflight              map[string]*Lease
	rates                 map[int]protocol.UserRate
	fences                map[int]int
	periodFences          map[accountingKey]int
	activity              activitySnapshot
	activityHistory       activityHistory
	closedActivity        map[int]map[string]int
	resources             int
	outboundFences        map[string]int
	hourly                *hourly.Controller
	hourlySequence        uint64
	hourlyApplied         uint64
}
type Lease struct {
	Info                                     Connection
	once                                     sync.Once
	registry                                 *Registry
	user                                     *userState
	cancel                                   func()
	accounting                               *accountingCounters
	accountingKey                            accountingKey
	tracked                                  bool
	finished                                 chan struct{}
	finishOnce                               sync.Once
	identity                                 string
	outbounds                                map[string]bool
	transit                                  bool
	bytes                                    atomic.Uint64
	sampledBytes                             uint64
	closed, nativeFinished, resourceReleased bool
	hourlyBinding                            *hourly.BindingKey
	hourlyController                         *hourly.Controller
	hourlyMu                                 sync.Mutex
	hourlyFlow                               *hourly.Flow
	hourlyClosed                             bool
	hourlySequence                           uint64
	hourlyReady                              bool
}
