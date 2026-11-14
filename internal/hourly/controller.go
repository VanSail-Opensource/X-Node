package hourly

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

var (
	ErrInvalid     = errors.New("invalid hourly admission")
	ErrUnavailable = errors.New("hourly admission is unavailable")
	ErrCapacity    = errors.New("hourly admission capacity exhausted")
	ErrRevoked     = errors.New("hourly admission was revoked")
)

type Controller struct {
	mu                               sync.RWMutex
	options                          Options
	session                          string
	stopped                          bool
	sequence, revision               uint64
	authorizations                   map[BindingKey]Authorization
	owners                           map[OwnerKey]*ownerState
	creditIndex                      sync.Map
	wake                             chan struct{}
	flows, permits, credits, samples atomic.Int64
	counterSequence                  atomic.Uint64
	demandCursor                     atomic.Uint64
	progressCursor                   atomic.Uint64
}

type ownerState struct {
	mu           sync.Mutex
	key          OwnerKey
	controller   *Controller
	bucket       *bucket
	incarnation  uint64
	lastSequence uint64
	flows        map[*Flow]struct{}
	permits      map[*Permit]struct{}
	credits      map[string]*creditState
	samples      map[sampleKey]*sampleCounter
	changed      chan struct{}
	creditLow    bool
}

type bucket struct {
	scope                   Scope
	incarnation             uint64
	grant                   *grantState
	pending                 *pendingDemand
	tokens, held, remainder uint64
	last                    time.Time
}

type grantState struct {
	grant    protocol.HourlyGrant
	deadline time.Time
	timer    Stopper
	drain    *Drain
}

type pendingDemand struct {
	nonce             string
	started, deadline time.Time
}

func NewController(options Options) *Controller {
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.AfterFunc == nil {
		options.AfterFunc = func(d time.Duration, fn func()) Stopper { return time.AfterFunc(d, fn) }
	}
	if options.Nonce == nil {
		options.Nonce = func() string {
			var b [16]byte
			if _, err := rand.Read(b[:]); err != nil {
				return ""
			}
			return hex.EncodeToString(b[:])
		}
	}
	options.MaxOwners = boundedLimit(options.MaxOwners, 8192)
	options.MaxFlows = boundedLimit(options.MaxFlows, 32768)
	options.MaxPermits = boundedLimit(options.MaxPermits, 65536)
	return &Controller{options: options, authorizations: map[BindingKey]Authorization{}, owners: map[OwnerKey]*ownerState{}, wake: make(chan struct{}, 1)}
}

func boundedLimit(value, maximum int) int {
	if value <= 0 || value > maximum {
		return maximum
	}
	return value
}

func (c *Controller) DemandWake() <-chan struct{} { return c.wake }
func (c *Controller) notify() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}
func (o *ownerState) changedOnly() { close(o.changed); o.changed = make(chan struct{}) }
func (o *ownerState) signal()      { o.changedOnly(); o.controller.notify() }

func (c *Controller) newOwner(key OwnerKey) *ownerState {
	return &ownerState{key: key, controller: c, flows: map[*Flow]struct{}{}, permits: map[*Permit]struct{}{}, credits: map[string]*creditState{}, samples: map[sampleKey]*sampleCounter{}, changed: make(chan struct{})}
}

// Only the controller's clock supplies this day; a received grant cannot move it.
func (o *ownerState) currentBucket(now time.Time) *bucket {
	day := now.UTC().Format(time.DateOnly)
	if o.bucket == nil || o.bucket.scope.DayUTC != day {
		o.incarnation++
		o.bucket = &bucket{scope: Scope{Owner: o.key, DayUTC: day}, incarnation: o.incarnation, last: now}
	}
	return o.bucket
}

func reserveCount(count *atomic.Int64, limit int) bool {
	for {
		old := count.Load()
		if old >= int64(limit) {
			return false
		}
		if count.CompareAndSwap(old, old+1) {
			return true
		}
	}
}

func validBinding(key BindingKey) bool {
	return protocol.ValidateHourlyOwner(protocol.HourlyOwner{ID: key.Owner.ID, Generation: key.Owner.Generation}) == nil && key.PrincipalID > 0 && protocol.ValidName(key.EnrollmentID) && protocol.ValidName(key.PeriodID)
}
