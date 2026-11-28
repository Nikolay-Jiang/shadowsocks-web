package agent

import "testing"

func TestLogBufferAndLineWriter(t *testing.T) {
	buf := NewLogBuffer(3)
	w := newLogLineWriter("server", buf)
	if _, err := w.Write([]byte("2026-01-01 INFO: ready\n2026-01-01 ERROR: broke\npartial")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(" line\n")); err != nil {
		t.Fatal(err)
	}
	entries := buf.Snapshot(10)
	if len(entries) != 3 {
		t.Fatalf("entries = %d", len(entries))
	}
	if entries[0].Level != "INFO" || entries[1].Level != "ERROR" {
		t.Fatalf("unexpected levels: %+v", entries)
	}
	if entries[2].Message != "partial line" {
		t.Fatalf("framing failed: %q", entries[2].Message)
	}

	buf.Append("agent", "WARN", "full")
	entries = buf.Snapshot(10)
	if len(entries) != 3 || entries[2].Message != "full" {
		t.Fatalf("ring replacement failed: %+v", entries)
	}
	buf.Drop(2)
	entries = buf.Snapshot(10)
	if len(entries) != 1 || entries[0].Message != "full" {
		t.Fatalf("drop failed: %+v", entries)
	}
}
