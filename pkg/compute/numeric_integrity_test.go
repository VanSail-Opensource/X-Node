package compute

import (
	"context"
	"math"
	"testing"
)

func TestResultCannotUseOverflowToInventFiniteEconomics(t *testing.T) {
	for _, task := range []Task{
		{ID: "mean", Kind: "forecast_quantiles_v1", Samples: []float64{math.MaxFloat64, math.MaxFloat64}},
		{ID: "revenue", Kind: "candidate_eval_v1", Candidates: []CandidateInput{{Price: 100, NetPrice: 100, Units: math.MaxFloat64}}},
	} {
		t.Run(task.Kind, func(t *testing.T) {
			batch := Batch{Version: Version, Tasks: []Task{task}}
			out, err := Run(context.Background(), batch)
			if err != nil {
				t.Fatal(err)
			}
			if out.Items[0].Quantiles != nil {
				out.Items[0].Quantiles.Mean = 1
			} else {
				out.Items[0].Candidates[0].Revenue = 1
				out.Items[0].Candidates[0].Contribution = 1
			}
			if ValidateResult(batch, out) == nil {
				t.Fatal("finite fabricated result matched overflowed expected arithmetic")
			}
		})
	}
}

func TestResultValidationRejectsInvalidOriginalBatch(t *testing.T) {
	for _, batch := range []Batch{
		{Version: "unknown-version", Tasks: []Task{{ID: "task", Kind: "forecast_quantiles_v1"}}},
		{Version: Version, Tasks: []Task{{ID: "task", Kind: "unknown-kernel"}}},
	} {
		_, hash, err := DigestBatch(batch)
		if err != nil {
			t.Fatal(err)
		}
		out := Results{Version: Version, InputHash: hash, Items: []Result{{ID: "task", Kind: batch.Tasks[0].Kind, Quantiles: &Quantiles{}}}}
		if ValidateResult(batch, out) == nil {
			t.Fatal("result validation accepted an unsupported original calculation")
		}
	}
}

func TestForecastMeanPreservesFiniteExtremeSamples(t *testing.T) {
	batch := Batch{Version: Version, Tasks: []Task{{ID: "large", Kind: "forecast_quantiles_v1", Samples: []float64{math.MaxFloat64, math.MaxFloat64}}}}
	out, err := Run(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if got := out.Items[0].Quantiles.Mean; got != math.MaxFloat64 {
		t.Fatal("finite forecast mean overflowed", got)
	}
	if err := ValidateResult(batch, out); err != nil {
		t.Fatal("stable mean failed result binding", err)
	}
}
