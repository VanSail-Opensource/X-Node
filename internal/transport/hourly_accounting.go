package transport

import (
	"net/http"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// HourlyAccounting reports this connection's historical-receipt compatibility,
// independently of local credit storage or permission to admit hourly payload.
func (c *Client) HourlyAccounting() bool { return c.hourlyAccounting.Load() || c.Hourly() }

func (c *Client) acceptHourlyAccounting(response *http.Response) {
	compatible := c.Hourly() // Existing live-v1 masters already understand samples.
	if response != nil {
		values := response.Header.Values(protocol.HourlyAccountingHeader)
		compatible = compatible || len(values) == 1 && values[0] == protocol.HourlyAccountingFormat
	}
	c.hourlyAccounting.Store(compatible)
}
