package compute

import (
	"context"
	"math"
	"testing"
)

func TestKernelsRejectInvalidInputAndCancelledFits(t *testing.T) {
	for _, tc := range []struct {
		name string
		task Task
	}{
		{"unknown", Task{ID: "a", Kind: "shell"}},
		{"nonfinite", Task{ID: "a", Kind: "forecast_quantiles_v1", Samples: []float64{math.NaN()}}},
		{"negative", Task{ID: "a", Kind: "forecast_quantiles_v1", Samples: []float64{-1}}},
		{"oversized", Task{ID: "a", Kind: "response_fit_v1", Observations: make([]ResponseObservation, 2049)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Run(context.Background(), Batch{Version: Version, Tasks: []Task{tc.task}}); err == nil {
				t.Fatal("invalid calculation accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, Batch{Version: Version, Tasks: []Task{{ID: "cancelled", Kind: "response_fit_v1", Observations: make([]ResponseObservation, 200)}}}); err == nil {
		t.Fatal("cancelled work ran")
	}
}

func TestCompressedResultRetainsBindingAndRejectsCorruption(t *testing.T) {
	b := Batch{Version: Version, Tasks: []Task{{ID: "series", Kind: "forecast_quantiles_v1", Samples: []float64{0, 10, 20, 30, 40}}}}
	out, err := Run(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	if q := out.Items[0].Quantiles; q.P10 != 4 || q.P50 != 20 || q.P90 != 36 || q.Mean != 20 {
		t.Fatal(q)
	}
	raw, err := Encode(out)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateResult(b, decoded); err != nil {
		t.Fatal(err)
	}
	decoded.InputHash = "wrong"
	if ValidateResult(b, decoded) == nil {
		t.Fatal("unbound result accepted")
	}
	if _, err = Decode([]byte("not-zstd")); err == nil {
		t.Fatal("corrupt compression accepted")
	}
	if _, err = Decode(make([]byte, MaxCompressedBytes+1)); err == nil {
		t.Fatal("oversized compression accepted")
	}
}

func TestCouponFeaturesArePartOfTheResponseModel(t *testing.T) {
	m := ResponseModel{Coefficients: [6]float64{0, 0, 0, 0, 1, 2}}
	plain := m.Predict(ResponseObservation{})
	coupon := m.Predict(ResponseObservation{CouponPresent: 1, CouponDiscount: .5})
	if coupon <= plain || plain != .5 {
		t.Fatal("coupon features ignored", plain, coupon)
	}
}
