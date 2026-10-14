// Package nlog captures redacted agent and Xray messages in a bounded stream.
package nlog

import (
	"io"
	"log/slog"
	"os"
	"sync/atomic"
)

var logger atomic.Pointer[slog.Logger]

func init() { Init(os.Stdout, slog.LevelInfo, false) }
func Init(out io.Writer, level slog.Level, _ bool) {
	if out == nil {
		out = os.Stdout
	}
	logger.Store(slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: level})))
}
func Core() *slog.Logger { return logger.Load() }
