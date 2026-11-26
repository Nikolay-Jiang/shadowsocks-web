package panel

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db    *sql.DB
	crypt *Crypt
}

const schema = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    port INTEGER NOT NULL,
    method TEXT NOT NULL,
    server_psk_enc BLOB NOT NULL,
    require_identity INTEGER NOT NULL DEFAULT 1,
    access_log INTEGER NOT NULL DEFAULT 0,
    apply_mode TEXT NOT NULL DEFAULT 'supervisor',
    agent_token_hash BLOB NOT NULL,
    agent_version TEXT NOT NULL DEFAULT '',
    last_seen INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'offline',
    revision INTEGER NOT NULL DEFAULT 1,
    applied_revision INTEGER NOT NULL DEFAULT 0,
    pending_full INTEGER NOT NULL DEFAULT 1,
    last_error TEXT NOT NULL DEFAULT '',
    tx INTEGER NOT NULL DEFAULT 0,
    rx INTEGER NOT NULL DEFAULT 0,
    tcp_live INTEGER NOT NULL DEFAULT 0,
    udp_sessions INTEGER NOT NULL DEFAULT 0,
    tracked_ips INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS nodes_token ON nodes(agent_token_hash);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    quota_bytes INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS node_users (
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    psk_enc BLOB NOT NULL,
    psk_hash BLOB NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    total_tx INTEGER NOT NULL DEFAULT 0,
    total_rx INTEGER NOT NULL DEFAULT 0,
    last_raw_tx INTEGER NOT NULL DEFAULT 0,
    last_raw_rx INTEGER NOT NULL DEFAULT 0,
    baseline_tx INTEGER NOT NULL DEFAULT 0,
    baseline_rx INTEGER NOT NULL DEFAULT 0,
    last_seen INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (node_id, user_id),
    UNIQUE (node_id, psk_hash)
);

CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    remote_ip TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS user_seq (
    id INTEGER PRIMARY KEY AUTOINCREMENT
);
`

func OpenStore(path string, crypt *Crypt) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db, crypt: crypt}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func now() int64 { return time.Now().Unix() }

func hashBytes(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func (s *Store) CreateNode(ctx context.Context, node Node, agentToken string) (Node, error) {
	if node.ID == "" {
		node.ID = "nd_" + randomToken(8)
	}
	if node.ApplyMode == "" {
		node.ApplyMode = "supervisor"
	}
	if node.Status == "" {
		node.Status = "offline"
	}
	psk, err := s.crypt.Encrypt([]byte(node.ServerPSK))
	if err != nil {
		return Node{}, err
	}
	ts := now()
	_, err = s.db.ExecContext(ctx, `INSERT INTO nodes
        (id,name,address,port,method,server_psk_enc,require_identity,access_log,apply_mode,
         agent_token_hash,status,revision,applied_revision,pending_full,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		node.ID, node.Name, node.Address, node.Port, node.Method, psk, boolInt(node.RequireIdentity),
		boolInt(node.AccessLog), node.ApplyMode, hashBytes([]byte(agentToken)), node.Status, 1, 0, 1, ts, ts)
	if err != nil {
		return Node{}, err
	}
	node.Revision = 1
	node.PendingFull = true
	node.CreatedAt, node.UpdatedAt = ts, ts
	return node, nil
}

func (s *Store) GetNode(ctx context.Context, id string) (Node, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,name,address,port,method,server_psk_enc,require_identity,
        access_log,apply_mode,agent_version,last_seen,status,revision,applied_revision,pending_full,last_error,
        tx,rx,tcp_live,udp_sessions,tracked_ips,created_at,updated_at FROM nodes WHERE id=?`, id)
	return scanNode(row, s.crypt)
}

func (s *Store) ListNodes(ctx context.Context) ([]Node, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,address,port,method,server_psk_enc,require_identity,
        access_log,apply_mode,agent_version,last_seen,status,revision,applied_revision,pending_full,last_error,
        tx,rx,tcp_live,udp_sessions,tracked_ips,created_at,updated_at FROM nodes ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		n, err := scanNode(rows, s.crypt)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

type nodeScanner interface {
	Scan(dest ...any) error
}

func scanNode(row nodeScanner, crypt *Crypt) (Node, error) {
	var n Node
	var psk []byte
	var requireID, accessLog, pendingFull int
	if err := row.Scan(&n.ID, &n.Name, &n.Address, &n.Port, &n.Method, &psk, &requireID, &accessLog,
		&n.ApplyMode, &n.AgentVersion, &n.LastSeen, &n.Status, &n.Revision, &n.AppliedRevision, &pendingFull,
		&n.LastError, &n.Tx, &n.Rx, &n.TcpLive, &n.UdpSessions, &n.TrackedIPs, &n.CreatedAt, &n.UpdatedAt); err != nil {
		return Node{}, err
	}
	plain, err := crypt.Decrypt(psk)
	if err != nil {
		return Node{}, err
	}
	n.ServerPSK = string(plain)
	n.RequireIdentity = requireID != 0
	n.AccessLog = accessLog != 0
	n.PendingFull = pendingFull != 0
	if n.Status == "online" && n.LastSeen < now()-45 {
		n.Status = "offline"
	}
	return n, nil
}

func (s *Store) UpdateNode(ctx context.Context, node Node) error {
	psk, err := s.crypt.Encrypt([]byte(node.ServerPSK))
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE nodes SET name=?,address=?,port=?,method=?,server_psk_enc=?,
        require_identity=?,access_log=?,apply_mode=?,revision=revision+1,pending_full=1,updated_at=? WHERE id=?`,
		node.Name, node.Address, node.Port, node.Method, psk, boolInt(node.RequireIdentity),
		boolInt(node.AccessLog), node.ApplyMode, now(), node.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) DeleteNode(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM nodes WHERE id=?`, id)
	return err
}

func (s *Store) FindNodeByToken(ctx context.Context, token string) (Node, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,name,address,port,method,server_psk_enc,require_identity,
        access_log,apply_mode,agent_version,last_seen,status,revision,applied_revision,pending_full,last_error,
        tx,rx,tcp_live,udp_sessions,tracked_ips,created_at,updated_at FROM nodes WHERE agent_token_hash=?`,
		hashBytes([]byte(token)))
	return scanNode(row, s.crypt)
}

func (s *Store) SetNodeReport(ctx context.Context, id string, revision int64, status, message, version string) error {
	ts := now()
	_, err := s.db.ExecContext(ctx, `UPDATE nodes SET status=?,last_error=?,agent_version=?,last_seen=?,
        applied_revision=CASE WHEN ? > applied_revision THEN ? ELSE applied_revision END,
        pending_full=CASE WHEN ? >= revision THEN 0 ELSE pending_full END,
        updated_at=? WHERE id=?`,
		status, message, version, ts, revision, revision, revision, ts, id)
	return err
}

func (s *Store) IncrementNodeRevision(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE nodes SET revision=revision+1,updated_at=? WHERE id=?`, now(), id)
	return err
}

func (s *Store) NextUserID(ctx context.Context) (string, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO user_seq DEFAULT VALUES`)
	if err != nil {
		return "", err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("u%05d", id), nil
}

func (s *Store) CreateUser(ctx context.Context, u User) (User, error) {
	if u.ID == "" {
		id, err := s.NextUserID(ctx)
		if err != nil {
			return User{}, err
		}
		u.ID = id
	}
	ts := now()
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(id,display_name,enabled,quota_bytes,expires_at,note,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?)`, u.ID, u.DisplayName, boolInt(u.Enabled), u.QuotaBytes, u.ExpiresAt, u.Note, ts, ts)
	if err != nil {
		return User{}, err
	}
	u.CreatedAt, u.UpdatedAt = ts, ts
	return u, nil
}

func (s *Store) GetUser(ctx context.Context, id string) (User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,display_name,enabled,quota_bytes,expires_at,note,created_at,updated_at
        FROM users WHERE id=?`, id)
	return scanUser(row)
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,display_name,enabled,quota_bytes,expires_at,note,created_at,updated_at
        FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func scanUser(row nodeScanner) (User, error) {
	var u User
	var enabled int
	if err := row.Scan(&u.ID, &u.DisplayName, &enabled, &u.QuotaBytes, &u.ExpiresAt, &u.Note, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return User{}, err
	}
	u.Enabled = enabled != 0
	return u, nil
}

func (s *Store) UpdateUser(ctx context.Context, u User) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET display_name=?,enabled=?,quota_bytes=?,expires_at=?,note=?,updated_at=?
        WHERE id=?`, u.DisplayName, boolInt(u.Enabled), u.QuotaBytes, u.ExpiresAt, u.Note, now(), u.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
	return err
}

func (s *Store) AssignUser(ctx context.Context, nodeID, userID, psk string) error {
	enc, err := s.crypt.Encrypt([]byte(psk))
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO node_users(node_id,user_id,psk_enc,psk_hash,enabled)
        VALUES (?,?,?,?,1)
        ON CONFLICT(node_id,user_id) DO UPDATE SET psk_enc=excluded.psk_enc,psk_hash=excluded.psk_hash,enabled=1`,
		nodeID, userID, enc, hashBytes([]byte(psk)))
	return err
}

func (s *Store) RemoveAssignment(ctx context.Context, nodeID, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM node_users WHERE node_id=? AND user_id=?`, nodeID, userID)
	return err
}

func (s *Store) AssignedNodeIDs(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id FROM node_users WHERE user_id=?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Store) RotateNodeToken(ctx context.Context, id, token string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE nodes SET agent_token_hash=?,updated_at=? WHERE id=?`,
		hashBytes([]byte(token)), now(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ListAssignmentsForUser(ctx context.Context, userID string) ([]Assignment, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id,user_id,psk_enc,enabled,total_tx,total_rx,last_raw_tx,
        last_raw_rx,baseline_tx,baseline_rx,last_seen FROM node_users WHERE user_id=? ORDER BY node_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAssignments(rows, s.crypt)
}

func (s *Store) ListAssignmentsForNode(ctx context.Context, nodeID string) ([]Assignment, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id,user_id,psk_enc,enabled,total_tx,total_rx,last_raw_tx,
        last_raw_rx,baseline_tx,baseline_rx,last_seen FROM node_users WHERE node_id=? ORDER BY user_id`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAssignments(rows, s.crypt)
}

func (s *Store) GetAssignment(ctx context.Context, nodeID, userID string) (Assignment, error) {
	row := s.db.QueryRowContext(ctx, `SELECT node_id,user_id,psk_enc,enabled,total_tx,total_rx,last_raw_tx,
        last_raw_rx,baseline_tx,baseline_rx,last_seen FROM node_users WHERE node_id=? AND user_id=?`, nodeID, userID)
	return scanAssignment(row, s.crypt)
}

func scanAssignments(rows *sql.Rows, crypt *Crypt) ([]Assignment, error) {
	var out []Assignment
	for rows.Next() {
		a, err := scanAssignment(rows, crypt)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func scanAssignment(row nodeScanner, crypt *Crypt) (Assignment, error) {
	var a Assignment
	var enc []byte
	var enabled int
	if err := row.Scan(&a.NodeID, &a.UserID, &enc, &enabled, &a.TotalTx, &a.TotalRx, &a.LastRawTx,
		&a.LastRawRx, &a.BaselineTx, &a.BaselineRx, &a.LastSeen); err != nil {
		return Assignment{}, err
	}
	plain, err := crypt.Decrypt(enc)
	if err != nil {
		return Assignment{}, err
	}
	a.PSK = string(plain)
	a.Enabled = enabled != 0
	return a, nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
