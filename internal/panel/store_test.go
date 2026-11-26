package panel

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestStoreMigratesDefaultPSKColumn(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "panel.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE users (
		id TEXT PRIMARY KEY,
		display_name TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		quota_bytes INTEGER NOT NULL DEFAULT 0,
		expires_at INTEGER NOT NULL DEFAULT 0,
		note TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	)`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	crypt, err := OpenCrypt(dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(dbPath, crypt)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	psk := "unused-in-this-test"
	user, err := store.CreateUser(context.Background(), User{DisplayName: "old", Enabled: true, DefaultPSK: psk})
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.UserDefaultPSK(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != psk {
		t.Fatalf("default psk = %q", got)
	}
}
