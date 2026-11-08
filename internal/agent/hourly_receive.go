package agent

import (
	"errors"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (a *Agent) validateHourlyConfiguration(config protocol.Config) error {
	for _, user := range config.Users {
		if user.Hourly != nil && (!a.checkHourlyHealth() || !a.Client.Hourly()) {
			return errors.New("hourly enforcement requires healthy negotiated support")
		}
	}
	return nil
}

func (a *Agent) receiveHourly(message protocol.Message) error {
	var grant protocol.HourlyGrant
	if err := protocol.Decode(message.Data, &grant); err != nil {
		return err
	}
	if err := protocol.ValidateHourlyGrant(grant); err != nil {
		return err
	}
	if !a.checkHourlyHealth() || !a.Client.Hourly() || grant.SessionID != a.Client.HourlySession() {
		return errors.New("hourly control session unavailable")
	}
	drain, err := a.hourly.controller.ApplyGrant(grant)
	ack := protocol.HourlyGrantAck{SessionID: grant.SessionID, Owner: grant.Owner, Nonce: grant.Nonce, Sequence: grant.Sequence, Applied: err == nil}
	if err != nil {
		ack.Reason = "stale_or_unavailable"
		a.Client.Send(protocol.New("hourly.grant.ack", "", 0, ack), false)
		return nil
	}
	a.hourly.ackMu.Lock()
	a.hourly.acks[grant.Owner] = hourlyGrantReceipt{ack: ack, drain: drain}
	a.hourly.ackMu.Unlock()
	return nil
}
