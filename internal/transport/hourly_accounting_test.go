package transport

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestHourlyAccountingReceiptRequiresExactCurrentConnectionSupport(t *testing.T) {
	for _, entry := range []struct {
		name     string
		values   []string
		accepted bool
	}{
		{"exact", []string{protocol.HourlyAccountingFormat}, true},
		{"missing", nil, false},
		{"version", []string{"v2"}, false},
		{"case", []string{"V1"}, false},
		{"whitespace", []string{"v1 "}, false},
		{"combined", []string{"v1,v2"}, false},
		{"duplicate", []string{"v1", "v2"}, false},
	} {
		t.Run(entry.name, func(t *testing.T) {
			client := New("", "")
			response := &http.Response{Header: http.Header{}}
			for _, value := range entry.values {
				response.Header.Add(protocol.HourlyAccountingHeader, value)
			}
			client.acceptHourlyAccounting(response)
			if client.HourlyAccounting() != entry.accepted || client.Hourly() || client.HourlySession() != "" {
				t.Fatal("receipt compatibility authorized live admission or accepted malformed support")
			}
			client.clearHourlySession()
			if client.HourlyAccounting() {
				t.Fatal("receipt compatibility survived a connection boundary")
			}
		})
	}
}

func TestHourlyAccountingReplaySurvivesAdmissionDisableWithoutMutatingFrames(t *testing.T) {
	client := New("", "")
	client.SetHourlyEnabled(true)
	offered := client.offerHourly(http.Header{})
	response := &http.Response{Header: http.Header{}}
	response.Header.Set(protocol.HourlyHeader, protocol.HourlyFormat)
	response.Header.Set(protocol.HourlySessionHeader, offered)
	client.acceptHourly(response, offered)
	client.acceptHourlyAccounting(response) // Existing live-v1 master compatibility.
	client.SetHourlyEnabled(false)
	if client.Hourly() || !client.HourlyAccounting() {
		t.Fatal("local storage failure discarded known receipt compatibility")
	}
	report := protocol.New("traffic.report", "mixed-journal", 0, protocol.TrafficReport{ID: "mixed-journal", Traffic: protocol.Traffic{1: {3, 4}}, HourlySamples: []protocol.HourlySample{{UserID: 1}}, DroppedHourlySamples: 1})
	filtered, send, err := client.hourlyMessage(report)
	if err != nil || !send || filtered.ID != report.ID || !bytes.Equal(filtered.Data, report.Data) {
		t.Fatal("receipt-only mode changed the immutable mixed journal", err)
	}
	for _, name := range []string{"hourly.demand", "hourly.grant.ack", "hourly.grant.acks", "hourly.credit.proofs"} {
		if _, send, err = client.hourlyMessage(protocol.New(name, "", 0, map[string]any{"session_id": offered})); err != nil || send {
			t.Fatal("receipt compatibility authorized a live hourly extension", name, err)
		}
	}
	client.clearHourlySession()
	client.acceptHourlyAccounting(&http.Response{Header: http.Header{}})
	if _, send, err = client.hourlyMessage(report); err != nil || send {
		t.Fatal("queued journal reused compatibility from an older connection", err)
	}
	if !bytes.Equal(filtered.Data, report.Data) {
		t.Fatal("fallback rewrote retained historical evidence")
	}
}
