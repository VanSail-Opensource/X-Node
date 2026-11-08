package agent

import "errors"

// A refusal is only constructed at a boundary that proves the mutation was not
// admitted, or after its exact terminal proof has already been durably stored.
// Storage errors and interrupted side effects must retain uncertain receipts.
type jobRefusal struct{ cause error }

func (e jobRefusal) Error() string { return e.cause.Error() }
func (e jobRefusal) Unwrap() error { return e.cause }
func refuseJob(err error) error    { return jobRefusal{cause: err} }
func definiteJobRefusal(err error) bool {
	var refusal jobRefusal
	return errors.As(err, &refusal)
}
