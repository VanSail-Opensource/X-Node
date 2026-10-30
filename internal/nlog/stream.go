package nlog

import (
	"fmt"
	xlog "github.com/xtls/xray-core/common/log"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Entry struct {
	Time   time.Time `json:"time"`
	Source string    `json:"source"`
	Text   string    `json:"text"`
}
type Stream struct {
	mu       sync.Mutex
	entries  []Entry
	secrets  map[string]bool
	replacer *strings.Replacer
	dropped  uint64
	out      io.Writer
	local    xlog.Handler
	observer atomic.Pointer[xrayObserver]
}

type xrayObserver struct {
	enabled func() bool
	observe func(string)
}

var capture atomic.Pointer[Stream]

func NewStream(out io.Writer) *Stream {
	s := &Stream{out: out, secrets: map[string]bool{}}
	capture.Store(s)
	return s
}
func (s *Stream) Secrets(values ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range values {
		if len(v) > 0 && len(s.secrets) < 200000 {
			s.secrets[v] = true
		}
	}
	s.buildReplacer()
}
func (s *Stream) SetSecrets(values ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets = map[string]bool{}
	for _, v := range values {
		if v != "" && len(s.secrets) < 200000 {
			s.secrets[v] = true
		}
	}
	s.buildReplacer()
}
func (s *Stream) buildReplacer() {
	keys := make([]string, 0, len(s.secrets))
	for k := range s.secrets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	pairs := make([]string, 0, len(keys)*2)
	for _, k := range keys {
		pairs = append(pairs, k, "[REDACTED]")
	}
	s.replacer = strings.NewReplacer(pairs...)
}
func (s *Stream) sanitize(text string) string {
	if s.replacer != nil {
		text = s.replacer.Replace(text)
	}
	if len(text) > 8192 {
		text = text[:8192] + " [truncated]"
	}
	return text
}
func (s *Stream) Redact(text string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sanitize(text)
}
func (s *Stream) Write(b []byte) (int, error) {
	s.append("agent", strings.TrimSpace(string(b)), true)
	return len(b), nil
}
func (s *Stream) append(source, text string, console bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	text = s.sanitize(text)
	if len(s.entries) >= 1024 {
		s.dropped++
		s.entries = append(s.entries[:0], s.entries[1:]...)
	}
	s.entries = append(s.entries, Entry{Time: time.Now().UTC(), Source: source, Text: text})
	if console && s.out != nil {
		_, _ = fmt.Fprintln(s.out, text)
	}
}
func (s *Stream) Drain() ([]Entry, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := append([]Entry(nil), s.entries...)
	dropped := s.dropped
	s.entries = nil
	s.dropped = 0
	return entries, dropped
}
func BindXray(local xlog.Handler) {
	if s := capture.Load(); s != nil {
		s.mu.Lock()
		s.local = local
		s.mu.Unlock()
		xlog.RegisterHandler(s)
	}
}

func RestoreXray() {
	if s := capture.Load(); s != nil {
		xlog.RegisterHandler(s)
	}
}

// SetXrayObserver installs a nonblocking observer for explicitly enabled
// native information logs without changing configured log output filtering.
func (s *Stream) SetXrayObserver(enabled func() bool, observe func(string)) {
	if enabled == nil || observe == nil {
		s.observer.Store(nil)
		return
	}
	s.observer.Store(&xrayObserver{enabled: enabled, observe: observe})
}

func xraySeverity(local xlog.Handler) xlog.Severity {
	if logger, ok := local.(xlog.SeverityLogger); ok {
		return logger.Severity()
	}
	return xlog.Severity_Info
}

func (s *Stream) Severity() xlog.Severity {
	s.mu.Lock()
	local := s.local
	s.mu.Unlock()
	level := xraySeverity(local)
	if observer := s.observer.Load(); observer != nil && observer.enabled() && level < xlog.Severity_Info {
		return xlog.Severity_Info
	}
	return level
}
func (s *Stream) Handle(msg xlog.Message) {
	s.mu.Lock()
	local := s.local
	s.mu.Unlock()
	if general, ok := msg.(*xlog.GeneralMessage); ok {
		if observer := s.observer.Load(); observer != nil && general.Severity == xlog.Severity_Info && observer.enabled() {
			observer.observe(fmt.Sprint(general.Content))
		}
		if general.Severity > xraySeverity(local) {
			return
		}
	}
	text := s.Redact(msg.String())
	s.append("xray", text, false)
	if local == nil {
		return
	}
	switch m := msg.(type) {
	case *xlog.AccessMessage:
		copy := *m
		copy.From = s.Redact(fmt.Sprint(m.From))
		copy.To = s.Redact(fmt.Sprint(m.To))
		copy.Reason = s.Redact(fmt.Sprint(m.Reason))
		copy.Email = s.Redact(m.Email)
		copy.Detour = s.Redact(m.Detour)
		local.Handle(&copy)
	case *xlog.GeneralMessage:
		local.Handle(&xlog.GeneralMessage{Severity: m.Severity, Content: text})
	default:
		local.Handle(&xlog.GeneralMessage{Severity: xlog.Severity_Info, Content: text})
	}
}
