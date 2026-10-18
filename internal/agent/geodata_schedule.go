package agent

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/geodata"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"time"
)

func geoPolicyKey(policy geodata.Policy) string { raw, _ := json.Marshal(policy); return string(raw) }

func (a *Agent) scheduleGeodata(policy geodata.Policy) {
	a.geoMu.Lock()
	defer a.geoMu.Unlock()
	key := geoPolicyKey(policy)
	if a.geoPolicy == key {
		return
	}
	a.geoPolicy, a.geoFailures = key, 0
	a.setGeodataNext(geodata.Next(policy, time.Now()))
}

func (a *Agent) setGeodataNext(next time.Time) {
	if next.IsZero() {
		a.geoNext.Store(0)
	} else {
		a.geoNext.Store(next.UnixNano())
	}
}

func (a *Agent) finishGeodata(policy geodata.Policy, err error) {
	a.geoMu.Lock()
	defer a.geoMu.Unlock()
	if a.geoPolicy != geoPolicyKey(policy) {
		return
	}
	now := time.Now()
	next := geodata.Next(policy, now)
	if err != nil && !next.IsZero() {
		retries := []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute}
		if a.geoFailures < len(retries) {
			next = now.Add(retries[a.geoFailures])
			a.geoFailures++
		} else {
			a.geoFailures = 0
		}
	} else {
		a.geoFailures = 0
	}
	a.setGeodataNext(next)
}

func (a *Agent) refreshGeodata(ctx context.Context, config protocol.Config, policy geodata.Policy) error {
	if !a.geoRunning.CompareAndSwap(false, true) {
		return errors.New("geodata refresh is already running")
	}
	defer a.geoRunning.Store(false)
	a.geoMu.Lock()
	if a.geoPolicy != geoPolicyKey(policy) {
		a.geoMu.Unlock()
		return errors.New("geodata policy was superseded")
	}
	a.geoNext.Store(0)
	a.geoMu.Unlock()
	a.nativeMu.Lock()
	defer a.nativeMu.Unlock()
	target, err := a.ensureAssets(ctx, config, policy, true)
	if err == nil {
		a.geoCandidate, a.geoCandidateKey = target, assetKey(config, policy)
	}
	a.finishGeodata(policy, err)
	return err
}
