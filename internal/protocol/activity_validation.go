package protocol

import (
	"errors"
	"net/netip"
)

func ValidateActivity(metrics UserMetrics) error {
	if len(metrics.ActiveIPObservations) > MaxActivityObservations {
		return errors.New("activity observation limit exceeded")
	}
	if metrics.SampledAt == nil {
		if len(metrics.ActiveIPObservations) != 0 || metrics.ObservationDrops != 0 {
			return errors.New("activity observations require a sample timestamp")
		}
		return nil
	}
	if metrics.SampledAt.IsZero() {
		return errors.New("invalid activity sample timestamp")
	}
	type key struct {
		user int
		ip   string
	}
	seen := make(map[key]bool, len(metrics.ActiveIPObservations))
	for _, observation := range metrics.ActiveIPObservations {
		id := key{observation.UserID, observation.IP}
		_, err := netip.ParseAddr(observation.IP)
		if err != nil || observation.UserID <= 0 || seen[id] || observation.LastActive.IsZero() || observation.LastActive.After(*metrics.SampledAt) || observation.Observations == 0 {
			return errors.New("invalid activity observation")
		}
		seen[id] = true
	}
	return nil
}
