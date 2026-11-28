package panel

import (
	"fmt"
	"strings"
	"time"
)

func formatBytes(v uint64) string {
	const unit = 1024
	if v < unit {
		return fmt.Sprintf("%dB", v)
	}
	div, exp := uint64(unit), 0
	for n := v / unit; n >= unit && exp < 4; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(v)/float64(div), "KMGTPE"[exp])
}

func formatDate(v int64) string {
	if v <= 0 {
		return "-"
	}
	return time.Unix(v, 0).UTC().Format("2006-01-02 15:04")
}

func dateInput(v int64) string {
	if v <= 0 {
		return ""
	}
	return time.Unix(v, 0).UTC().Format("2006-01-02")
}

func levelClass(level string) string {
	switch strings.ToUpper(level) {
	case "ERROR", "FATAL":
		return "bad"
	case "WARN":
		return "warn"
	default:
		return "muted"
	}
}

func statusClass(status string) string {
	switch status {
	case "online", "applied":
		return "ok"
	case "error", "degraded":
		return "bad"
	default:
		return "muted"
	}
}

func shortID(id string) string {
	if len(id) <= 6 {
		return id
	}
	return id[:6] + "..."
}
