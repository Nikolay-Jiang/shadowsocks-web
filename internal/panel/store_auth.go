package panel

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const sessionTTL = 24 * time.Hour

func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return fmt.Sprintf("argon2id$v=19$m=65536,t=3,p=2$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func (s *Store) AdminCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&n)
	return n, err
}

func (s *Store) CreateAdmin(ctx context.Context, username, password string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO admins(username,password_hash,created_at) VALUES (?,?,?)`,
		username, hash, now())
	return err
}

func (s *Store) FindAdmin(ctx context.Context, username string) (int64, string, error) {
	var id int64
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT id,password_hash FROM admins WHERE username=? AND disabled=0`, username).
		Scan(&id, &hash)
	return id, hash, err
}

func (s *Store) CreateSession(ctx context.Context, adminID int64) (token, csrf string, err error) {
	token = randomToken(32)
	csrf = randomToken(32)
	ts := now()
	_, err = s.db.ExecContext(ctx, `INSERT INTO sessions(token_hash,admin_id,csrf,created_at,expires_at)
        VALUES (?,?,?,?,?)`, hashBytes([]byte(token)), adminID, csrf, ts, ts+int64(sessionTTL/time.Second))
	if err != nil {
		return "", "", err
	}
	return token, csrf, nil
}

type Session struct {
	AdminID  int64
	Username string
	CSRF     string
}

func (s *Store) GetSession(ctx context.Context, token string) (Session, error) {
	var out Session
	err := s.db.QueryRowContext(ctx, `SELECT a.id,a.username,s.csrf FROM sessions s
        JOIN admins a ON a.id=s.admin_id
        WHERE s.token_hash=? AND s.expires_at>? AND a.disabled=0`, hashBytes([]byte(token)), now()).
		Scan(&out.AdminID, &out.Username, &out.CSRF)
	return out, err
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, hashBytes([]byte(token)))
	return err
}

func (s *Store) CleanupSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at<=?`, now())
	return err
}

var errNotFound = errors.New("not found")

func isNotFound(err error) bool { return errors.Is(err, sql.ErrNoRows) || errors.Is(err, errNotFound) }
