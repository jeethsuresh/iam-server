package db

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestSQLiteCreateAndVerifyUser(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	sdb, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sdb.db.Close()

	// Empty DB seeds demo user; clear for isolated test
	if _, err := sdb.db.Exec(`DELETE FROM users`); err != nil {
		t.Fatal(err)
	}

	if err := sdb.CreateUser("alice", "hunter2"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if !sdb.GetUser("alice", "hunter2") {
		t.Fatal("GetUser should accept correct password")
	}
	if sdb.GetUser("alice", "wrong") {
		t.Fatal("GetUser should reject wrong password")
	}
	if sdb.GetUser("nobody", "hunter2") {
		t.Fatal("GetUser should reject unknown user")
	}
	if err := sdb.CreateUser("alice", "other"); err == nil {
		t.Fatal("duplicate username should fail")
	}
}

func TestSQLiteMigratesLegacySchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.db")
	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	);`)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	sdb, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sdb.db.Close()

	var n int
	if err := sdb.db.QueryRow(`SELECT count(*) FROM pragma_table_info('users') WHERE name='salt'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("expected salt column after migrate, got n=%d err=%v", n, err)
	}
}

func TestSQLiteDeleteUser(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "del.db")
	sdb, err := NewSQLiteDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sdb.Close()
	if err := sdb.TruncateUsers(); err != nil {
		t.Fatal(err)
	}
	if err := sdb.CreateUser("gone", "pw"); err != nil {
		t.Fatal(err)
	}
	if !sdb.GetUser("gone", "pw") {
		t.Fatal("user should exist")
	}
	if err := sdb.DeleteUser("gone"); err != nil {
		t.Fatal(err)
	}
	if sdb.GetUser("gone", "pw") {
		t.Fatal("user should be deleted")
	}
	if err := sdb.DeleteUser("nobody"); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteNewSQLiteDBAt_SeedsWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seed.db")
	sdb, err := NewSQLiteDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sdb.Close()
	var n int
	if err := sdb.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected demo seed user, count=%d", n)
	}
	if !sdb.GetUser("user@localhost:8080", "password") {
		t.Fatal("demo user should authenticate")
	}
}

func TestSQLiteTruncateUsers(t *testing.T) {
	dir := t.TempDir()
	sdb, err := NewSQLiteDBAt(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sdb.Close()
	if err := sdb.TruncateUsers(); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = sdb.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	if n != 0 {
		t.Fatalf("truncate: %d", n)
	}
}
