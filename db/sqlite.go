package db

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteDB struct {
	db *sql.DB
}

// NewSQLiteDB opens ./user_data.db with the expected users schema.
func NewSQLiteDB() (*SQLiteDB, error) {
	return openSQLiteDB("./user_data.db")
}

// NewSQLiteDBAt opens an SQLite database at path (for tests or alternate locations).
func NewSQLiteDBAt(path string) (*SQLiteDB, error) {
	return openSQLiteDB(path)
}

// Close releases the database connection.
func (s *SQLiteDB) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func openSQLiteDB(path string) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	if err := ensureSQLiteUsersTable(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	inst := &SQLiteDB{db: db}

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		_ = db.Close()
		return nil, err
	}
	if n == 0 {
		if err := seedDemoSQLiteUser(db); err != nil {
			log.Printf("Error seeding SQLite demo user: %v", err)
		}
	}

	return inst, nil
}

func ensureSQLiteUsersTable(db *sql.DB) error {
	var tableExists int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='users'`).Scan(&tableExists); err != nil {
		return err
	}
	if tableExists == 0 {
		return createSQLiteUsersTable(db)
	}

	var saltCols int
	if err := db.QueryRow(`SELECT count(*) FROM pragma_table_info('users') WHERE name='salt'`).Scan(&saltCols); err != nil {
		return err
	}
	if saltCols == 0 {
		if _, err := db.Exec(`DROP TABLE users`); err != nil {
			return fmt.Errorf("sqlite migrate: drop legacy users: %w", err)
		}
		return createSQLiteUsersTable(db)
	}
	return nil
}

func createSQLiteUsersTable(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		salt TEXT NOT NULL
	);`)
	return err
}

func seedDemoSQLiteUser(db *sql.DB) error {
	salt, err := generateSalt(16)
	if err != nil {
		return err
	}
	hashed, err := hashPassword("password", salt, PEPPER)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO users (username, password, salt) VALUES (?, ?, ?)`,
		"user@localhost:8080", hashed, salt)
	return err
}

// CreateUser creates a new user in the database

func (s *SQLiteDB) CreateUser(username string, password string) error {
	salt, err := generateSalt(16)
	if err != nil {
		return err
	}
	hashedPassword, err := hashPassword(password, salt, PEPPER)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`INSERT INTO users (username, password, salt) VALUES (?, ?, ?)`, username, hashedPassword, salt)
	return err
}

// GetUser returns true if username and password match a stored user.

func (s *SQLiteDB) GetUser(username string, password string) bool {
	var storedHash, storedSalt string
	err := s.db.QueryRow(`SELECT password, salt FROM users WHERE username = ?`, username).Scan(&storedHash, &storedSalt)
	if err != nil {
		if err == sql.ErrNoRows {
			return false
		}
		log.Printf("Error querying database: %v", err)
		return false
	}
	return verifyPassword(storedHash, password, storedSalt, PEPPER)
}

// TruncateUsers deletes all rows from users (e.g. test isolation).
func (s *SQLiteDB) TruncateUsers() error {
	_, err := s.db.Exec(`DELETE FROM users`)
	return err
}

// DeleteUser deletes a user from the database

func (s *SQLiteDB) DeleteUser(username string) error {

	deleteUserSQL := `DELETE FROM users WHERE username = ?`
	_, err := s.db.Exec(deleteUserSQL, username)
	if err != nil {
		log.Printf("Error deleting user: %v", err)
		return err
	}
	return nil
}
