package hourly

import (
	"sort"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// StopAdmission is a permanent process-shutdown fence. Taking the controller's
// write lock joins every Begin that already crossed the admission boundary.
// It neither invokes native interrupt hooks nor waits for network delivery;
// FreezeCredit can now cancel unstarted permits and preserve exact totals.
// Later session or authorization callbacks cannot reopen this controller.
func (c *Controller) StopAdmission() {
	c.mu.Lock()
	c.stopped = true
	c.session = ""
	c.mu.Unlock()
}

// CreditIDs includes old sessions until a durable final proof owns their totals.
func (c *Controller) CreditIDs() []string {
	var ids []string
	c.creditIndex.Range(func(key, _ any) bool { ids = append(ids, key.(string)); return true })
	sort.Strings(ids)
	return ids
}

// ForgetCredit follows successful Store.Seal. The store now retains the exact
// proof through acknowledgement; its permanently claimed marker prevents replay.
func (c *Controller) ForgetCredit(proof protocol.HourlyCreditProof) error {
	if protocol.ValidateHourlyProof(proof) != nil || proof.Recovery {
		return ErrInvalid
	}
	value, ok := c.creditIndex.Load(proof.Install.ReservationID)
	if !ok {
		return nil
	}
	credit := value.(*creditState)
	o := credit.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if !credit.frozen || credit.held != 0 || credit.installed.marker.active() || credit.installed.install != proof.Install || credit.admitted != [2]uint64{proof.AdmittedUploadBytes, proof.AdmittedDownloadBytes} || credit.available() != proof.UnusedBytes {
		return ErrRevoked
	}
	if o.credits[proof.Install.ReservationID] != credit {
		return nil
	}
	delete(o.credits, proof.Install.ReservationID)
	c.creditIndex.Delete(proof.Install.ReservationID)
	c.credits.Add(-1)
	o.signal()
	return nil
}
