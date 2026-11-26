package panel

import "context"

func (s *Store) AddAudit(ctx context.Context, actor, action, targetType, targetID, detail, remoteIP string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_log(ts,actor,action,target_type,target_id,detail,remote_ip)
        VALUES (?,?,?,?,?,?,?)`, now(), actor, action, targetType, targetID, detail, remoteIP)
	return err
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,ts,actor,action,target_type,target_id,detail,remote_ip
        FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.TargetType, &e.TargetID, &e.Detail, &e.RemoteIP); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
