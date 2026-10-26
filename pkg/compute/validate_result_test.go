package compute

import (
	"context"
	"testing"
)

func TestResultCannotInventForecastRevenueOrModelValidation(t *testing.T) {
	for _, task := range []Task{
		{ID: "forecast", Kind: "forecast_quantiles_v1", Samples: []float64{1, 2, 3}},
		{ID: "price", Kind: "candidate_eval_v1", Candidates: []CandidateInput{{Price: 100, NetPrice: 50, Units: 1}}},
		{ID: "model", Kind: "response_fit_v1", Observations: make([]ResponseObservation, 200)},
	} {
		t.Run(task.Kind, func(t *testing.T) {
			b := Batch{Version: Version, Tasks: []Task{task}}
			out, err := Run(context.Background(), b)
			if err != nil {
				t.Fatal(err)
			}
			if err = ValidateResult(b, out); err != nil {
				t.Fatal(err)
			}
			switch task.Kind {
			case "forecast_quantiles_v1":
				out.Items[0].Quantiles.Mean += 100
			case "candidate_eval_v1":
				out.Items[0].Candidates[0].Revenue += 100
			case "response_fit_v1":
				out.Items[0].Model.Validated = true
			}
			if ValidateResult(b, out) == nil {
				t.Fatal("invented numerical evidence accepted")
			}
		})
	}
}
