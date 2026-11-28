package panel

import (
	"context"
	"strings"
	"time"

	"github.com/Nikolay-Jiang/shadowsocks-web/internal/protocol"
)

const (
	logRetentionDays = 7
	logMaxPerNode    = 5000
	logMessageMax    = 4096
)

// AppendLogs stores a batch from one agent and keeps the per-node history
// bounded. Logging is best effort from the agent's point of view, but a
// database failure is returned so the agent can retry the batch.
func (s *Store) AppendLogs(ctx context.Context, nodeID string, logs []protocol.LogEntry) error {
	if len(logs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO node_logs(node_id,ts,source,level,message) VALUES (?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, entry := range logs {
		if entry.Message == "" {
			continue
		}
		message := entry.Message
		if len(message) > logMessageMax {
			message = message[:logMessageMax] + "..."
		}
		source := entry.Source
		if source == "" {
			source = "server"
		}
		level := strings.ToUpper(entry.Level)
		if level == "" {
			level = "INFO"
		}
		ts := entry.Time
		if ts == 0 {
			ts = time.Now().Unix()
		}
		if _, err := stmt.ExecContext(ctx, nodeID, ts, source, level, message); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM node_logs WHERE node_id=? AND ts<?`,
		nodeID, time.Now().Add(-logRetentionDays*24*time.Hour).Unix()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM node_logs WHERE node_id=? AND id NOT IN (
		SELECT id FROM node_logs WHERE node_id=? ORDER BY id DESC LIMIT ?)`,
		nodeID, nodeID, logMaxPerNode); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListNodeLogs(ctx context.Context, nodeID, level string, limit int) ([]protocol.LogEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	query := `SELECT ts,source,level,message FROM node_logs WHERE node_id=?`
	args := []any{nodeID}
	if level != "" {
		query += ` AND level=?`
		args = append(args, strings.ToUpper(level))
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.LogEntry
	for rows.Next() {
		var e protocol.LogEntry
		if err := rows.Scan(&e.Time, &e.Source, &e.Level, &e.Message); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
