package hourly

import (
	"context"
	"testing"
	"time"
)

func TestCreditAgentIdentityIsEmptyOnlyBeforeFirstObligation(t *testing.T) {
	store, _ := openCreditFixture(t)
	const another = "99999999999999999999999999999999"
	if !store.MatchesAgent(creditFixtureInstall(1).AgentID) || !store.MatchesAgent(another) || store.MatchesAgent("") || store.MatchesAgent("invalid") {
		t.Fatal("new journal identity matching is not fail closed")
	}
	installCreditFixture(t, store)
	if !store.MatchesAgent(creditFixtureInstall(1).AgentID) || store.MatchesAgent(another) {
		t.Fatal("issued journal lost its immutable agent identity")
	}
}

func TestCreditIdentityReadDoesNotWaitForPersistence(t *testing.T) {
	store, _ := openCreditFixture(t)
	installCreditFixture(t, store)
	entered, release := make(chan struct{}), make(chan struct{})
	write := store.write
	store.write = func(path string, raw []byte) error {
		close(entered)
		<-release
		return write(path, raw)
	}
	done := make(chan error, 1)
	go func() {
		i := creditFixtureInstall(2)
		i.ReservationID = "second-credit"
		_, err := store.Install(context.Background(), i)
		done <- err
	}()
	defer func() {
		close(release)
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("persistence fixture never started")
	}
	matched := make(chan bool, 1)
	go func() { matched <- store.MatchesAgent(creditFixtureInstall(1).AgentID) }()
	select {
	case ok := <-matched:
		if !ok {
			t.Fatal("blocked write changed immutable identity")
		}
	case <-time.After(time.Second):
		t.Fatal("agent health check waited on credit disk I/O")
	}
}
