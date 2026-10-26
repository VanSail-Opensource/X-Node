package compute

import (
	"encoding/json"
	"errors"
)

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
			expected := EmpiricalForecast(t.Samples)
			if !near(q.P10, expected.P10) || !near(q.P50, expected.P50) || !near(q.P90, expected.P90) || !near(q.Mean, expected.Mean) {
				return errors.New("forecast does not match observations")
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
			if err := validateModel(t.Observations, *r.Model); err != nil {
				return err
			}
		case "candidate_eval_v1":
			if len(r.Candidates) != len(t.Candidates) {
				return errors.New("invalid candidate result count")
			}
			for j, c := range r.Candidates {
				if c.Price != t.Candidates[j].Price || !valid(c.Probability) || c.Probability < 0 || c.Probability > 1 || !valid(c.Revenue) || !valid(c.Contribution) {
					return errors.New("invalid candidate result")
				}
				input := t.Candidates[j]
				probability := t.Model.Predict(input.Features)
				revenue := float64(input.NetPrice) * input.Units * probability
				if !near(c.Probability, probability) || !near(c.Revenue, revenue) || !near(c.Contribution, revenue-input.Cost) {
					return errors.New("candidate economics do not match input")
				}
			}
		}
	}
	_, err = json.Marshal(out)
	return err
}
