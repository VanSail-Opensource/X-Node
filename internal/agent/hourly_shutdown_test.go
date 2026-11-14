package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/transport"
)

func shutdownHourlyFixture(t *testing.T) (*Agent, string, hourly.BindingKey, protocol.HourlyCreditInstall) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "hourly-credits.json")
	store, err := hourly.OpenCreditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	controller := hourly.NewController(hourly.Options{})
	key := hourly.BindingKey{Owner: hourly.OwnerKey{ID: "account", Generation: 7}, EnrollmentID: "enrollment", PeriodID: "paid", PrincipalID: 1}
	if !controller.ApplyAuthorization(1, 1, []hourly.Authorization{{Key: key, PaidThrough: time.Now().Add(time.Hour)}}) {
		t.Fatal("hourly authorization rejected")
	}
	install := protocol.HourlyCreditInstall{ReservationID: "active", IssueSequence: 1, Owner: protocol.HourlyOwner{ID: key.Owner.ID, Generation: key.Owner.Generation}, DayUTC: time.Now().UTC().Format(time.DateOnly), AgentID: "11111111111111111111111111111111", BootID: "22222222222222222222222222222222", SessionID: "33333333333333333333333333333333", ByteCeiling: 1000, Kind: "free"}
	controller.SetSession(install.SessionID)
	credit, err := store.Install(context.Background(), install)
	if err != nil {
		t.Fatal(err)
	}
	if err = controller.InstallCredit(credit); err != nil {
		t.Fatal(err)
	}
	h := &hourlyRuntime{controller: controller, store: store, installed: map[string]protocol.HourlyCreditInstall{install.ReservationID: install}, acks: map[protocol.HourlyOwner]hourlyGrantReceipt{}}
	client := transport.New("wss://unused.invalid", "fixture-token")
	client.OnHourlySession = func(session string) { controller.SetSession(session) }
	return &Agent{Client: client, hourly: h}, path, key, install
}

func TestHourlyShutdownJoinsAcceptedInstallAndRetirementBeforeSnapshot(t *testing.T) {
	a, path, key, first := shutdownHourlyFixture(t)
	h := a.hourly
	if !h.beginOperation() {
		t.Fatal("fixture could not enter accepted command")
	}
	// Hold an accepted install at its real durable-install/activation boundary.
	// Shutdown must neither omit this reservation nor close its store beneath it.
	second := first
	second.ReservationID, second.IssueSequence, second.Kind = "in-flight", 2, "extra"
	credit, err := h.store.Install(context.Background(), second)
	if err != nil {
		h.operations.Done()
		t.Fatal(err)
	}
	h.creditMu.Lock()
	h.installed[second.ReservationID] = second
	h.creditMu.Unlock()
	var workers sync.WaitGroup
	workers.Add(1)
	workerPending, operationPending := true, true
	defer func() {
		if workerPending {
			workers.Done()
		}
		if operationPending {
			h.operations.Done()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.shutdownHourly(ctx, &workers) }()
	await(t, func() bool { return h.stopping.Load() })
	if h.beginOperation() {
		h.operations.Done()
		t.Fatal("shutdown admitted another durable command")
	}
	if _, err := a.hourlyCommand(context.Background(), protocol.HourlyCreditInstallCommand, nil); err == nil {
		t.Fatal("command dispatcher bypassed the shutdown gate")
	}
	await(t, func() bool {
		flow, err := h.controller.OpenFlow(key, func() {})
		if flow != nil {
			flow.Close()
		}
		return errors.Is(err, hourly.ErrRevoked)
	})
	select {
	case err := <-done:
		t.Fatal("cleanup crossed a live retirement worker", err)
	default:
	}
	workers.Done()
	workerPending = false
	if !h.store.Healthy() {
		t.Fatal("cleanup closed the store beneath an accepted install")
	}
	select {
	case err := <-done:
		t.Fatal("cleanup omitted an accepted install", err)
	default:
	}
	if err = h.controller.InstallCredit(credit); !errors.Is(err, hourly.ErrRevoked) {
		t.Fatal("accepted install reopened admission after the fence", err)
	}
	h.forgetInstalledCredit(second.ReservationID)
	if _, err = h.store.SealUnclaimed(context.Background(), credit); err != nil {
		t.Fatal("accepted unclaimed reservation could not finish safely", err)
	}
	h.operations.Done()
	operationPending = false
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if h.store.Healthy() || len(h.controller.CreditIDs()) != 0 {
		t.Fatal("completed shutdown left live admission authority")
	}
	reopened, err := hourly.OpenCreditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	proofs := reopened.Recovery()
	if len(proofs) != 2 {
		t.Fatal("shutdown lost an original reservation", proofs)
	}
	for i, install := range []protocol.HourlyCreditInstall{first, second} {
		proof := proofs[i]
		if proof.Install != install || proof.Recovery || proof.UnknownBytes != 0 || proof.AdmittedUploadBytes != 0 || proof.AdmittedDownloadBytes != 0 || proof.UnusedBytes != install.ByteCeiling || protocol.ValidateHourlyProof(proof) != nil {
			t.Fatal("shutdown fabricated or discarded a financial partition", proof)
		}
	}
}

func TestHourlyShutdownDeadlinePreservesUnsealedRecoveryAndDoesNotCloseInflightStore(t *testing.T) {
	for _, blocker := range []string{"command", "retirement"} {
		t.Run(blocker, func(t *testing.T) {
			a, path, _, install := shutdownHourlyFixture(t)
			h := a.hourly
			var workers sync.WaitGroup
			var release func()
			if blocker == "command" {
				if !h.beginOperation() {
					t.Fatal("fixture could not enter accepted command")
				}
				release = h.operations.Done
			} else {
				workers.Add(1)
				release = workers.Done
			}
			var released sync.Once
			defer released.Do(release)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- a.shutdownHourly(ctx, &workers) }()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("deadline reported successful financial cleanup", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("in-flight work made shutdown unbounded")
			}
			if !h.store.Healthy() || len(h.store.Recovery()) != 0 {
				t.Fatal("deadline closed or sealed beneath in-flight work")
			}
			released.Do(release)
			await(t, func() bool { return !h.store.Healthy() })
			reopened, err := hourly.OpenCreditStore(path)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			proofs := reopened.Recovery()
			if len(proofs) != 1 || proofs[0].Install != install || !proofs[0].Recovery || proofs[0].UnknownBytes != install.ByteCeiling || proofs[0].UnusedBytes != 0 || proofs[0].AdmittedUploadBytes != 0 || proofs[0].AdmittedDownloadBytes != 0 {
				t.Fatal("incomplete shutdown invented usage or refundable credit", proofs)
			}
		})
	}
}
