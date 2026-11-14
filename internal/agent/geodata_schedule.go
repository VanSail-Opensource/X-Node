package agent

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/geodata"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"os"
	"path/filepath"
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
	// Use a separate owned stage so download/cleanup cannot touch a serving or
	// pending native generation. Only publication takes the activation lock.
	err := a.stageGeodataRefresh(ctx, config, policy)
	a.finishGeodata(policy, err)
	return err
}

func (a *Agent) stageGeodataRefresh(ctx context.Context, config protocol.Config, policy geodata.Policy) error {
	if len(policy.Assets) == 0 {
		return nil
	}
	dir := filepath.Join(a.Dir, "geodata")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(dir, ".assets-refresh-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	target, err := prepareAssets(ctx, stage, config, policy, true)
	if err == nil {
		if err = a.nativeMu.LockContext(ctx); err == nil {
			if target, err = geodata.AdoptPrepared(dir, target); err == nil {
				a.geoCandidate, a.geoCandidateKey = target, assetKey(config, policy)
			}
			a.nativeMu.Unlock()
		}
	}
	return err
}
