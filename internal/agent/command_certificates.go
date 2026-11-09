package agent

import (
	"context"
	"errors"

	"github.com/VanSail-Opensource/X-Node/internal/cert"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// The dispatch snapshot comes from actor-owned desired state, including failed
// targets; accepted Store.Configuration may still describe an older profile.
func (a *Agent) startCertificateCommand(lifetime context.Context, id string, snapshot protocol.Config, input protocol.CertificateRunArgs, eligibility ...error) error {
	return a.Jobs.Start(lifetime, id, protocol.CertificateRunCommand, func(parent context.Context, progress func(any)) (any, error) {
		if len(eligibility) > 0 && eligibility[0] != nil {
			return nil, refuseJob(eligibility[0])
		}
		ctx, cancel := context.WithTimeout(parent, protocol.CommandTimeout(protocol.CertificateRunCommand))
		defer cancel()
		key, _ := cert.ProfileKey(snapshot, input.ProfileID)
		candidate := cert.Candidate{ProfileID: input.ProfileID, Key: key}
		if a.Store.Revision() != input.ExpectedRevision {
			return nil, refuseJob(errors.New("CERTIFICATE_SUPERSEDED"))
		}
		phase := "issuing"
		if input.Action == "renew" {
			phase = "renewing"
		}
		progress(protocol.CertificateRunProgress{ProfileID: input.ProfileID, Action: input.Action, Phase: phase})
		var err error
		candidate, err = a.Certificates.Acquire(ctx, lifetime, snapshot, input, id, func() bool { return a.Store.Revision() == input.ExpectedRevision })
		if err != nil {
			progress(protocol.CertificateRunProgress{ProfileID: input.ProfileID, Action: input.Action, Phase: "failed"})
			if err.Error() == "CERTIFICATE_SUPERSEDED" || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, refuseJob(err)
			}
			return a.Certificates.Result(candidate, input.Action, a.Runtime.Ready()), err
		}
		progress(protocol.CertificateRunProgress{ProfileID: input.ProfileID, Action: input.Action, Phase: "applying"})
		done := make(chan error, 1)
		request := reloadRequest{ID: id, Done: done, Context: ctx, ExpectedRevision: input.ExpectedRevision, Certificate: &candidate}
		select {
		case a.notify <- request:
		case <-ctx.Done():
			err = ctx.Err()
		}
		if err == nil {
			select {
			case err = <-done:
			case <-ctx.Done():
				err = ctx.Err()
			}
		}
		if err != nil {
			code := "CERTIFICATE_ACTIVATION_FAILED"
			if a.Store.Revision() != input.ExpectedRevision {
				code = "CERTIFICATE_SUPERSEDED"
			}
			a.Certificates.Failed(candidate, code)
			progress(protocol.CertificateRunProgress{ProfileID: input.ProfileID, Action: input.Action, Phase: "failed"})
			return a.Certificates.Result(candidate, input.Action, a.Runtime.Ready()), errors.New(code)
		}
		progress(protocol.CertificateRunProgress{ProfileID: input.ProfileID, Action: input.Action, Phase: "idle"})
		return protocol.CertificateRunResult{ProfileID: candidate.ProfileID, Action: input.Action, Fingerprint: candidate.Fingerprint, Expires: candidate.Expires, Applied: true, Ready: a.Runtime.Ready()}, nil
	})
}
