package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/cert"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/transport"
)

func TestUnknownCommandsCannotOccupyWorkersOrJournal(t *testing.T) {
	jobs, results := executionJobs(t, t.TempDir())
	a := &Agent{Jobs: jobs}
	for i := range maxJobHistory + 1 {
		m := protocol.New("command", fmt.Sprint(i), 0, map[string]any{"name": "unsupported.command"})
		if err := a.command(context.Background(), m); err == nil {
			t.Fatal("unknown command was admitted instead of rejected before execution")
		}
	}
	if len(jobs.Snapshot()) != 0 || len(jobs.slots) != 0 || len(results) != 0 {
		t.Fatal("unsupported commands consumed executor or receipt capacity")
	}
	if _, err := os.Stat(jobs.path); !os.IsNotExist(err) {
		t.Fatal("unsupported command wrote a durable intent", err)
	}
}

func TestRepeatableWorkSurvivesFullOrUnverifiableMutationHistory(t *testing.T) {
	commands := []string{"ddns", "ddns.run", "runtime.reload", "geodata.refresh", "firewall.bans.sync", "firewall.bans.update", "firewall.geoip.sync", "firewall.confirm", protocol.HourlyCreditInstallCommand, protocol.HourlyCreditSealCommand, protocol.HourlyCreditAckCommand}
	for _, broken := range []bool{false, true} {
		for _, command := range commands {
			t.Run(fmt.Sprintf("%s/broken=%t", command, broken), func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "jobs.json")
				var entries []JobResult
				for i := range maxJobHistory {
					entries = append(entries, JobResult{ID: fmt.Sprint(i), Command: "update.install", Status: "uncertain"})
				}
				raw, err := json.Marshal(entries)
				if err != nil {
					t.Fatal(err)
				}
				if broken {
					raw = []byte("unverifiable journal")
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				results := make(chan protocol.Message, 2)
				jobs, err := NewJobs(dir, journalSink(results))
				if err != nil {
					t.Fatal(err)
				}
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				operation := func(context.Context, func(any)) (any, error) {
					calls++
					return map[string]bool{"applied": true}, nil
				}
				for range 2 {
					if err := jobs.Start(context.Background(), "unrelated-sync", command, operation); err != nil {
						t.Fatal("unrelated repeatable operation was fenced by mutation history", err)
					}
					if result := journalResult(t, results); result.Status != "completed" {
						t.Fatal("unrelated repeatable operation failed", result)
					}
				}
				if calls != 1 {
					t.Fatal("live duplicate replay repeated the operation")
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("repeatable operation replaced retained mutation evidence", err)
				}
			})
		}
	}
}

func TestRepeatedDDNSFailuresCannotPoisonUnrelatedMutationCapacity(t *testing.T) {
	jobs, results := executionJobs(t, t.TempDir())
	for i := range maxJobHistory + 1 {
		if err := jobs.Start(context.Background(), fmt.Sprint(i), "ddns", func(context.Context, func(any)) (any, error) {
			return nil, errors.New("discovery provider is unavailable")
		}); err != nil {
			t.Fatal(err)
		}
		if result := journalResult(t, results); result.Status != "failed" {
			t.Fatal("repeatable discovery failure became an irreversible mutation obligation", result)
		}
		awaitUtilitySlots(t, jobs)
	}
	if err := jobs.Start(context.Background(), "independent", "update.install", func(context.Context, func(any)) (any, error) {
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if result := journalResult(t, results); result.Status != "completed" {
		t.Fatal("DDNS failures exhausted an unrelated durable command", result)
	}
}

func TestAccountingAndInspectionCommandsRemainAvailableUnderBulkAndControlPressure(t *testing.T) {
	jobs, results := executionJobs(t, t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	block := func(ctx context.Context, _ func(any)) (any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	for _, id := range []string{"download-one", "download-two"} {
		if err := jobs.Start(ctx, id, "geodata.refresh", block); err != nil {
			t.Fatal(err)
		}
	}
	if err := jobs.StartControl(ctx, "control-wait", "firewall.bans.update", block); err != nil {
		t.Fatal(err)
	}
	certificates := cert.NewPool(t.TempDir())
	defer certificates.Stop()
	a := &Agent{Jobs: jobs, Client: transport.New("", ""), Certificates: certificates}
	for _, command := range []string{protocol.HourlyCreditInstallCommand, "certificates.get"} {
		if err := a.command(ctx, protocol.New("command", command, 0, map[string]any{"name": command})); err != nil {
			t.Fatal("unrelated feature inherited occupied worker capacity", command, err)
		}
		result := journalResult(t, results)
		if result.ID != command {
			t.Fatal("unrelated command did not execute independently", result)
		}
		if command == "certificates.get" && result.Status != "completed" {
			t.Fatal("read command failed under utility pressure", result)
		}
	}
	cancel()
	for range 3 {
		journalResult(t, results)
	}
}

func TestRepeatableReplayBindsNormalizedArgumentsWithoutPersistingThem(t *testing.T) {
	jobs, results := executionJobs(t, t.TempDir())
	a := &Agent{Jobs: jobs, Client: transport.New("", "")}
	message := func(args string) protocol.Message {
		return protocol.Message{V: 1, Type: "command", ID: "credit", Data: []byte(`{"name":"` + protocol.HourlyCreditInstallCommand + `","args":` + args + `}`)}
	}
	if err := a.command(context.Background(), message(`{"owner":"fixture","sequence":9007199254740993}`)); err != nil {
		t.Fatal(err)
	}
	first := journalResult(t, results)
	if err := a.command(context.Background(), message(`{ "sequence":9007199254740993, "owner":"fixture" }`)); err != nil {
		t.Fatal("equivalent arguments did not replay", err)
	}
	second := journalResult(t, results)
	if first.Finished != second.Finished {
		t.Fatal("same request was executed again instead of replayed")
	}
	if err := a.command(context.Background(), message(`{"sequence":9007199254740992,"owner":"fixture"}`)); err == nil || !strings.Contains(err.Error(), "different command arguments") {
		t.Fatal("a different exact integer reused one request identity", err)
	}
	if _, err := os.Stat(jobs.path); !os.IsNotExist(err) {
		t.Fatal("repeatable command arguments created a disk receipt", err)
	}
}

func TestRedundantMutationReceiptsAreArchivedBeforeRetirement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jobs.json")
	raw, err := json.Marshal([]JobResult{
		{ID: "ddns-old", Command: "ddns", Status: "uncertain"},
		{ID: "credit-old", Command: protocol.HourlyCreditInstallCommand, Status: "uncertain"},
		{ID: "upgrade-old", Command: "update.install", Status: "uncertain"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		jobs, err := NewJobs(dir, func(protocol.Message, bool) bool { return true })
		if err != nil || jobs.recovery != "" {
			t.Fatal("native journal ownership could not be recovered", err, jobs.recovery)
		}
		history := jobs.Snapshot()
		if len(history) != 1 || history[0].ID != "upgrade-old" || history[0].Status != "uncertain" {
			t.Fatal("native replay receipts blocked unrelated work, or upgrade evidence was lost", history)
		}
	}
	archives, err := filepath.Glob(path + ".legacy-*")
	if err != nil || len(archives) != 1 {
		t.Fatal("retirement did not preserve one exact evidence copy", err, archives)
	}
	archived, err := os.ReadFile(archives[0])
	if err != nil || !bytes.Equal(archived, raw) {
		t.Fatal("retirement changed original mutation evidence", err)
	}
}

func TestMalformedDurableCommandArgumentsCannotExhaustUncertainCapacity(t *testing.T) {
	a, _ := activationFixture(t)
	defer a.Certificates.Stop()
	jobs, results := executionJobs(t, t.TempDir())
	a.Jobs = jobs
	for index := range maxJobHistory + 1 {
		for _, input := range []struct {
			name string
			args any
		}{
			{"firewall.apply", map[string]any{"policy": "invalid"}},
			{"update.install", map[string]any{"version": 23}},
		} {
			message := protocol.New("command", fmt.Sprintf("%s-%d", input.name, index), 0, map[string]any{"name": input.name, "args": input.args})
			if err := a.command(context.Background(), message); err != nil {
				t.Fatal(err)
			}
			if result := journalResult(t, results); result.Status != "failed" || strings.Contains(result.Error, "capacity") {
				t.Fatal("pre-mutation shape refusal became protected uncertainty", result)
			}
			awaitUtilitySlots(t, jobs)
		}
	}
	if err := jobs.Start(context.Background(), "valid-later", "update.rollback", func(context.Context, func(any)) (any, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if result := journalResult(t, results); result.Status != "completed" {
		t.Fatal("invalid earlier requests poisoned later mutation capacity", result)
	}
}
