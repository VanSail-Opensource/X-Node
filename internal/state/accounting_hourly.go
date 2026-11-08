package state

import (
	"fmt"
	"math"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// A separate bound prevents history samples from consuming native billing space.
const MaxHourlyTrafficEntries = 8192

func (m *memoryTraffic) dropHourly(count uint64) {
	m.droppedHourly += min(count, ^uint64(0)-m.droppedHourly)
}

func (m *memoryTraffic) addHourly(samples []protocol.HourlySample) {
	if len(samples) > MaxHourlyTrafficEntries {
		m.dropHourly(uint64(len(samples) - MaxHourlyTrafficEntries))
		samples = samples[:MaxHourlyTrafficEntries]
	}
	for _, sample := range samples {
		if protocol.ValidateHourlySample(sample) != nil {
			m.dropHourly(1)
			continue
		}
		if sample.UploadBytes == 0 && sample.DownloadBytes == 0 {
			continue
		}
		key := hourlySampleKey(sample)
		old, exists := m.hourly[key]
		if !exists {
			if len(m.hourly) >= MaxHourlyTrafficEntries {
				m.dropHourly(1)
				continue
			}
			if m.hourly == nil {
				m.hourly = map[string]protocol.HourlySample{}
			}
			m.hourly[key] = sample
			continue
		}
		remaining := uint64(math.MaxInt64) - old.UploadBytes - old.DownloadBytes
		if sample.UploadBytes > remaining || sample.DownloadBytes > remaining-sample.UploadBytes {
			m.dropHourly(1)
			continue
		}
		old.UploadBytes += sample.UploadBytes
		old.DownloadBytes += sample.DownloadBytes
		if sample.From.Before(old.From) {
			old.From = sample.From
		}
		if sample.Through.After(old.Through) {
			old.Through = sample.Through
		}
		m.hourly[key] = old
	}
}

func hourlySampleKey(s protocol.HourlySample) string {
	return fmt.Sprintf("%s:%d:%s:%d:%s:%s:%d:%d:%d", s.Owner.ID, s.Owner.Generation, s.EnrollmentID, s.UserID, s.AccountingPeriod, s.DayUTC, s.CounterGeneration, s.From.UTC().Unix()/60, s.Through.UTC().Unix()/60)
}
