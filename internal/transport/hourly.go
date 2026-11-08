package transport

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (c *Client) SetHourlyEnabled(enabled bool) {
	c.hourlyMu.Lock()
	defer c.hourlyMu.Unlock()
	changed := c.hourlyEnabled.Swap(enabled) != enabled
	if !enabled {
		c.clearHourlySessionLocked()
	}
	if changed && c.Connected() {
		select {
		case c.reset <- struct{}{}:
		default:
		}
	}
}

func (c *Client) Hourly() bool { return c.hourlyNegotiated.Load() }

func (c *Client) HourlySession() string {
	if !c.Hourly() {
		return ""
	}
	if session := c.hourlySession.Load(); session != nil {
		return session.(string)
	}
	return ""
}

func (c *Client) setHourlySession(session string) {
	previous, _ := c.hourlySession.Load().(string)
	c.hourlySession.Store(session)
	if previous != session && c.OnHourlySession != nil {
		c.OnHourlySession(session)
	}
}

func (c *Client) clearHourlySession() {
	c.hourlyMu.Lock()
	defer c.hourlyMu.Unlock()
	c.hourlyAccounting.Store(false)
	c.clearHourlySessionLocked()
}

func (c *Client) clearHourlySessionLocked() {
	c.hourlyNegotiated.Store(false)
	c.setHourlySession("")
}

func (c *Client) offerHourly(headers http.Header) string {
	if !c.hourlyEnabled.Load() {
		return ""
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ""
	}
	session := hex.EncodeToString(nonce[:])
	headers.Set(protocol.HourlyHeader, protocol.HourlyFormat)
	headers.Set(protocol.HourlySessionHeader, session)
	return session
}

func (c *Client) acceptHourly(response *http.Response, offered string) {
	c.hourlyMu.Lock()
	defer c.hourlyMu.Unlock()
	if offered == "" || !c.hourlyEnabled.Load() || response == nil || response.Header.Get(protocol.HourlyHeader) != protocol.HourlyFormat || response.Header.Get(protocol.HourlySessionHeader) != offered {
		return
	}
	c.hourlyNegotiated.Store(true)
	c.setHourlySession(offered)
}
