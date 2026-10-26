package compute

import (
	"context"
	"math"
)

// ResponseObservation is a bounded, non-sensitive price exposure with a closed outcome.
type ResponseObservation struct {
	LogPrice       float64 `json:"logPrice"`
	Activity       float64 `json:"activity"`
	Renewals       float64 `json:"renewals"`
	Converted      bool    `json:"converted"`
	CouponPresent  float64 `json:"couponPresent"`
	CouponDiscount float64 `json:"couponDiscount"`
}

// ResponseModel uses a regularized logistic response and chronological holdout.
type ResponseModel struct {
	Coefficients   [6]float64 `json:"coefficients"`
	Samples        int        `json:"samples"`
	Holdout        int        `json:"holdout"`
	Brier          float64    `json:"brier"`
	BaselineBrier  float64    `json:"baselineBrier"`
	Bias           float64    `json:"bias"`
	PriceVariation bool       `json:"priceVariation"`
	Validated      bool       `json:"validated"`
}

func sigmoid(v float64) float64 { return 1 / (1 + math.Exp(-max(-30, min(30, v)))) }

func (m ResponseModel) Predict(o ResponseObservation) float64 {
	x := o.features()
	v := 0.0
	for i := range x {
		v += m.Coefficients[i] * x[i]
	}
	return sigmoid(v)
}

// FitResponse performs deterministic bounded gradient fitting without simulations.
// A propensity model alone cannot validate a causal price response: publication
// additionally requires original out-of-time forecasts and operational gates.
func FitResponse(ctx context.Context, rows []ResponseObservation) (ResponseModel, error) {
	if len(rows) > 2048 {
		rows = rows[len(rows)-2048:]
	}
	m := ResponseModel{Samples: len(rows)}
	if len(rows) < 20 {
		return m, nil
	}
	split := len(rows) * 4 / 5
	success := 0.0
	low, high := rows[0].LogPrice, rows[0].LogPrice
	for _, o := range rows[:split] {
		if o.Converted {
			success++
		}
		low = min(low, o.LogPrice)
		high = max(high, o.LogPrice)
	}
	prior := (success + 1) / float64(split+2)
	m.Coefficients[0] = math.Log(prior / (1 - prior))
	m.PriceVariation = high-low > .1
	for iteration := 0; iteration < 100; iteration++ {
		if err := ctx.Err(); err != nil {
			return ResponseModel{}, err
		}
		gradient := [6]float64{}
		for _, o := range rows[:split] {
			y := 0.0
			if o.Converted {
				y = 1
			}
			d := m.Predict(o) - y
			x := o.features()
			for j := range x {
				gradient[j] += d * x[j]
			}
		}
		for j := range gradient {
			regularizer := 0.0
			if j > 0 {
				regularizer = .01 * m.Coefficients[j]
			}
			m.Coefficients[j] -= .1 * (gradient[j]/float64(split) + regularizer)
		}
	}
	for _, o := range rows[split:] {
		y := 0.0
		if o.Converted {
			y = 1
		}
		p := m.Predict(o)
		m.Brier += (p - y) * (p - y)
		m.BaselineBrier += (prior - y) * (prior - y)
		m.Bias += p - y
		m.Holdout++
	}
	m.Brier /= float64(m.Holdout)
	m.BaselineBrier /= float64(m.Holdout)
	m.Bias /= float64(m.Holdout)
	m.Validated = m.Samples >= 200 && m.Holdout >= 40 && m.PriceVariation && m.Brier < m.BaselineBrier && math.Abs(m.Bias) < .1 && m.Coefficients[1] <= 0
	return m, nil
}

func (o ResponseObservation) features() [6]float64 {
	return [6]float64{1, o.LogPrice, o.Activity, o.Renewals, o.CouponPresent, o.CouponDiscount}
}
