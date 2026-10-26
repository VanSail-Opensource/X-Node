package compute

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"slices"
)

func Digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

func valid(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

func Validate(b Batch) error {
	raw, _, err := DigestBatch(b)
	if err != nil || len(raw) > MaxInputBytes || b.Version != Version || len(b.Tasks) == 0 || len(b.Tasks) > MaxItems {
		return errors.New("invalid calculation batch")
	}
	seen := map[string]bool{}
	for _, t := range b.Tasks {
		if t.ID == "" || len(t.ID) > 128 || seen[t.ID] || len(t.Samples) > 32768 || len(t.Observations) > 2048 || len(t.Candidates) > 101 {
			return errors.New("invalid calculation input")
		}
		seen[t.ID] = true
		switch t.Kind {
		case "forecast_quantiles_v1", "response_fit_v1", "candidate_eval_v1":
		default:
			return errors.New("unsupported calculation kernel")
		}
		for _, v := range t.Samples {
			if !valid(v) || v < 0 {
				return errors.New("invalid sample")
			}
		}
		for _, o := range t.Observations {
			for _, v := range o.features() {
				if !valid(v) {
					return errors.New("invalid observation")
				}
			}
		}
		for _, v := range t.Model.Coefficients {
			if !valid(v) {
				return errors.New("invalid model")
			}
		}
		for _, c := range t.Candidates {
			if c.Price < 0 || c.Price > 1e12 || c.NetPrice < 0 || c.NetPrice > c.Price || !valid(c.Units) || !valid(c.Cost) || c.Units < 0 || c.Cost < 0 {
				return errors.New("invalid candidate")
			}
			for _, v := range c.Features.features() {
				if !valid(v) {
					return errors.New("invalid candidate features")
				}
			}
		}
	}
	return nil
}

func Run(ctx context.Context, b Batch) (Results, error) {
	if err := Validate(b); err != nil {
		return Results{}, err
	}
	_, hash, _ := DigestBatch(b)
	out := Results{Version: Version, InputHash: hash, Items: make([]Result, 0, len(b.Tasks))}
	for _, t := range b.Tasks {
		if err := ctx.Err(); err != nil {
			return Results{}, err
		}
		r := Result{ID: t.ID, Kind: t.Kind}
		switch t.Kind {
		case "forecast_quantiles_v1":
			q := EmpiricalForecast(t.Samples)
			r.Quantiles = &q
		case "response_fit_v1":
			m, err := FitResponse(ctx, t.Observations)
			if err != nil {
				return Results{}, err
			}
			r.Model = &m
		case "candidate_eval_v1":
			for _, c := range t.Candidates {
				p := t.Model.Predict(c.Features)
				revenue := float64(c.NetPrice) * c.Units * p
				r.Candidates = append(r.Candidates, Candidate{Price: c.Price, Probability: p, Revenue: revenue, Contribution: revenue - c.Cost})
			}
		}
		out.Items = append(out.Items, r)
	}
	return out, nil
}

func EmpiricalForecast(samples []float64) Quantiles {
	values := make([]float64, 0, len(samples))
	mean := 0.0
	for _, v := range samples {
		if v >= 0 && valid(v) {
			values = append(values, v)
			mean += v
		}
	}
	if len(values) == 0 {
		return Quantiles{}
	}
	slices.Sort(values)
	mean /= float64(len(values))
	q := func(p float64) float64 {
		x := p * float64(len(values)-1)
		i := int(x)
		j := min(i+1, len(values)-1)
		return values[i] + (values[j]-values[i])*(x-float64(i))
	}
	return Quantiles{P10: q(.1), P50: q(.5), P90: q(.9), Mean: mean}
}

// ValidateResult checks the exact task set, finite numeric output and ordering.
// The master separately rechecks financial policy and all authoritative versions.
func ValidateResult(b Batch, out Results) error {
	_, hash, err := DigestBatch(b)
	if err != nil || out.Version != Version || out.InputHash != hash || len(out.Items) != len(b.Tasks) {
		return errors.New("calculation result does not match input")
	}
	for i, r := range out.Items {
		t := b.Tasks[i]
		if r.ID != t.ID || r.Kind != t.Kind {
			return errors.New("calculation result task mismatch")
		}
		switch t.Kind {
		case "forecast_quantiles_v1":
			q := r.Quantiles
			if q == nil || !valid(q.P10) || !valid(q.P50) || !valid(q.P90) || !valid(q.Mean) || q.P10 < 0 || q.P10 > q.P50 || q.P50 > q.P90 || q.Mean < 0 {
				return errors.New("invalid forecast result")
			}
		case "response_fit_v1":
			if r.Model == nil || r.Model.Samples != len(t.Observations) {
				return errors.New("invalid fitted model")
			}
			for _, v := range r.Model.Coefficients {
				if !valid(v) {
					return errors.New("invalid fitted coefficient")
				}
			}
			if !valid(r.Model.Brier) || !valid(r.Model.Bias) || !valid(r.Model.BaselineBrier) {
				return errors.New("invalid fitted diagnostics")
			}
		case "candidate_eval_v1":
			if len(r.Candidates) != len(t.Candidates) {
				return errors.New("invalid candidate result count")
			}
			for j, c := range r.Candidates {
				if c.Price != t.Candidates[j].Price || !valid(c.Probability) || c.Probability < 0 || c.Probability > 1 || !valid(c.Revenue) || !valid(c.Contribution) {
					return errors.New("invalid candidate result")
				}
			}
		}
	}
	_, err = json.Marshal(out)
	return err
}
