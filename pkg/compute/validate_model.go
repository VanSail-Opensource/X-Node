package compute

import (
	"errors"
	"math"
)

func near(a, b float64) bool { return math.Abs(a-b) <= 1e-9*max(1, math.Abs(a), math.Abs(b)) }

// Validate the submitted diagnostics against original observations in one
// linear pass, without repeating gradient fitting on the master.
func validateModel(rows []ResponseObservation, m ResponseModel) error {
	if len(rows) < 20 {
		if m != (ResponseModel{Samples: len(rows)}) {
			return errors.New("invalid prior model")
		}
		return nil
	}
	split := len(rows) * 4 / 5
	low, high, success := rows[0].LogPrice, rows[0].LogPrice, 0.0
	for _, o := range rows[:split] {
		low, high = min(low, o.LogPrice), max(high, o.LogPrice)
		if o.Converted {
			success++
		}
	}
	prior := (success + 1) / float64(split+2)
	brier, baseline, bias := 0.0, 0.0, 0.0
	for _, o := range rows[split:] {
		y := 0.0
		if o.Converted {
			y = 1
		}
		p := m.Predict(o)
		brier += (p - y) * (p - y)
		baseline += (prior - y) * (prior - y)
		bias += p - y
	}
	holdout := len(rows) - split
	brier /= float64(holdout)
	baseline /= float64(holdout)
	bias /= float64(holdout)
	validated := len(rows) >= 200 && holdout >= 40 && high-low > .1 && brier < baseline && math.Abs(bias) < .1 && m.Coefficients[1] <= 0
	if m.Holdout != holdout || m.PriceVariation != (high-low > .1) || m.Validated != validated || !near(m.Brier, brier) || !near(m.BaselineBrier, baseline) || !near(m.Bias, bias) {
		return errors.New("fitted diagnostics do not match observations")
	}
	return nil
}
