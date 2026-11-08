package xray

import (
	"context"
	"io"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/xtls/xray-core/common/buf"
)

type nativeHourlyPermit struct {
	n        int
	beginErr error
	admitted *int
	outcomes *[]hourly.Outcome
}

func (p *nativeHourlyPermit) Bytes() int { return p.n }
func (p *nativeHourlyPermit) Begin() error {
	if p.beginErr == nil {
		*p.admitted += p.n
	}
	return p.beginErr
}
func (p *nativeHourlyPermit) Complete(outcome hourly.Outcome) {
	*p.outcomes = append(*p.outcomes, outcome)
}

func nativeHourlyAcquirer(limit int, admitted *int, outcomes *[]hourly.Outcome) hourlyAcquire {
	return func(ctx context.Context, _ hourly.Direction, want, minimum int) (hourlyHandoff, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := min(want, limit)
		if minimum > n {
			n = minimum
		}
		return &nativeHourlyPermit{n: n, admitted: admitted, outcomes: outcomes}, nil
	}
}

func nativeHourlyBuffer(payload string) *buf.Buffer {
	b := buf.NewWithSize(int32(max(len(payload), 1)))
	copy(b.Extend(int32(len(payload))), payload)
	return b
}

type nativeHourlySource struct {
	mb    buf.MultiBuffer
	err   error
	reads int
}

func (s *nativeHourlySource) ReadMultiBuffer() (buf.MultiBuffer, error) {
	s.reads++
	mb, err := s.mb, s.err
	s.mb, s.err = nil, io.EOF
	return mb, err
}
