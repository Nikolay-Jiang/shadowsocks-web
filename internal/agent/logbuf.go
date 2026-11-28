package agent

import (
	"bytes"
	"strings"
	"sync"
	"time"

	"github.com/Nikolay-Jiang/shadowsocks-web/internal/protocol"
)

const (
	logBufferEntries = 2000
	logLineMax       = 4096
	logBatchMax      = 200
)

// LogBuffer is a bounded in-memory queue of unsent node log lines.
type LogBuffer struct {
	mu      sync.Mutex
	entries []protocol.LogEntry
	max     int
}

func NewLogBuffer(max int) *LogBuffer {
	if max <= 0 {
		max = logBufferEntries
	}
	return &LogBuffer{max: max}
}

func (b *LogBuffer) Append(source, level, message string) {
	if message == "" {
		return
	}
	if len(message) > logLineMax {
		message = message[:logLineMax] + "..."
	}
	entry := protocol.LogEntry{
		Time:    time.Now().Unix(),
		Source:  source,
		Level:   level,
		Message: message,
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.entries) == b.max {
		copy(b.entries, b.entries[1:])
		b.entries[len(b.entries)-1] = entry
		return
	}
	b.entries = append(b.entries, entry)
}

// Snapshot returns at most limit entries without removing them. The caller
// calls Drop after the report is accepted so a failed upload can retry.
func (b *LogBuffer) Snapshot(limit int) []protocol.LogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	if limit <= 0 || limit > len(b.entries) {
		limit = len(b.entries)
	}
	out := make([]protocol.LogEntry, limit)
	copy(out, b.entries[:limit])
	return out
}

func (b *LogBuffer) Drop(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n >= len(b.entries) {
		b.entries = nil
		return
	}
	if n > 0 {
		copy(b.entries, b.entries[n:])
		b.entries = b.entries[:len(b.entries)-n]
	}
}

func logLevel(line string) string {
	upper := strings.ToUpper(line)
	switch {
	case strings.Contains(upper, "ERROR"), strings.Contains(upper, "FATAL"):
		return "ERROR"
	case strings.Contains(upper, "WARN"):
		return "WARN"
	case strings.Contains(upper, "DEBUG"):
		return "DEBUG"
	default:
		return "INFO"
	}
}

// logLineWriter frames arbitrary writes from a child process into lines.
type logLineWriter struct {
	source string
	buf    *LogBuffer

	mu      sync.Mutex
	partial []byte
}

func newLogLineWriter(source string, buf *LogBuffer) *logLineWriter {
	return &logLineWriter{source: source, buf: buf}
}

func (w *logLineWriter) Write(p []byte) (int, error) {
	n := len(p)
	w.mu.Lock()
	defer w.mu.Unlock()
	for len(p) != 0 {
		if i := bytes.IndexByte(p, '\n'); i >= 0 {
			line := append(w.partial, p[:i]...)
			w.partial = nil
			w.emit(line)
			p = p[i+1:]
			continue
		}
		w.partial = append(w.partial, p...)
		if len(w.partial) > logLineMax {
			line := w.partial
			w.partial = nil
			w.emit(line)
		}
		break
	}
	return n, nil
}

func (w *logLineWriter) emit(line []byte) {
	text := strings.TrimRight(string(line), "\r")
	if strings.TrimSpace(text) == "" {
		return
	}
	w.buf.Append(w.source, logLevel(text), text)
}
