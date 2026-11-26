package panel

import (
	"context"

	"github.com/Nikolay-Jiang/shadowsocks-web/internal/protocol"
)

func (s *Store) ApplyStats(ctx context.Context, nodeID string, report protocol.AgentReport) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	ts := now()
	if _, err := tx.ExecContext(ctx, `UPDATE nodes SET tx=?,rx=?,tcp_live=?,udp_sessions=?,tracked_ips=?,last_seen=?,updated_at=? WHERE id=?`,
		report.Stats.Global.Tx, report.Stats.Global.Rx, report.Stats.Global.TcpLive,
		report.Stats.Global.UdpSessions, report.Stats.Global.TrackedIPs, ts, ts, nodeID); err != nil {
		return err
	}
	for _, u := range report.Stats.Users {
		if u.ID == "" || u.ID == "anonymous" {
			continue
		}
		lastSeen := int64(0)
		if u.LastSeen > 0 && u.LastSeen < uint64(ts) {
			lastSeen = ts - int64(u.LastSeen)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE node_users SET
            total_tx=total_tx + CASE WHEN ? >= last_raw_tx THEN ? - last_raw_tx ELSE ? END,
            total_rx=total_rx + CASE WHEN ? >= last_raw_rx THEN ? - last_raw_rx ELSE ? END,
            last_raw_tx=?, last_raw_rx=?, last_seen=?
            WHERE node_id=? AND user_id=?`,
			u.Tx, u.Tx, u.Tx, u.Rx, u.Rx, u.Rx, u.Tx, u.Rx, lastSeen, nodeID, u.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) NodeUsers(ctx context.Context, nodeID string) ([]protocol.UserSpec, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT u.id,n.psk_enc FROM users u
        JOIN node_users n ON n.user_id=u.id
        WHERE n.node_id=? AND u.enabled=1 AND n.enabled=1 ORDER BY u.id`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.UserSpec
	for rows.Next() {
		var id string
		var enc []byte
		if err := rows.Scan(&id, &enc); err != nil {
			return nil, err
		}
		plain, err := s.crypt.Decrypt(enc)
		if err != nil {
			return nil, err
		}
		out = append(out, protocol.UserSpec{ID: id, PSK: string(plain), Enabled: true})
	}
	return out, rows.Err()
}
