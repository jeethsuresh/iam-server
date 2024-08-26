package db

import (
	"database/sql"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteDB struct {
	db *sql.DB
}

var dbInstance SQLiteDB

func init() {

	flag := false
	if _, err := os.Stat("./user_data.db"); err != nil {
		if os.IsNotExist(err) {
			flag = true
		}
	}

	// Open (or create) the SQLite database
	db, err := sql.Open("sqlite3", "./user_data.db")
	if err != nil {
		log.Fatal(err)
	}

	if flag {

		SeedDB(db)
	}

	defer db.Close()
}

func NewDB() *SQLiteDB {
	if dbInstance.db != nil {
		return &dbInstance
	}
	db, err := sql.Open("sqlite3", "./user_data.db")
	if err != nil {
		log.Fatal(err)
	}
	dbInstance = SQLiteDB{db}

	return &dbInstance
}

func SeedDB(db *sql.DB) {

	// Create the table if it does not exist
	createTableSQL := `CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	);`
	_, err := db.Exec(createTableSQL)
	if err != nil {
		log.Fatal(err)
	}

	// Insert sample data
	username := "user@localhost:8080"
	password := "password"

	insertUserSQL := `INSERT INTO users (id, username, password) VALUES (?, ?, ?)`
	_, err = db.Exec(insertUserSQL, 1, username, password)
	if err != nil {
		log.Fatal(err)
	}
}

// CreateUser creates a new user in the database

func (s *SQLiteDB) CreateUser(username string, password string) error {

	insertUserSQL := `INSERT INTO users (username, password) VALUES (?, ?)`
	_, err := s.db.Exec(insertUserSQL, username, password)
	if err != nil {
		return err
	}
	return nil
}

// GetUser returns a user from the database

func (s *SQLiteDB) GetUser(username string, password string) bool {
	getUserSQL := `SELECT * FROM users WHERE username = ? AND password = ?`
	rows, err := s.db.Query(getUserSQL, username, password)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	return rows.Next()
}

// DeleteUser deletes a user from the database

func (s *SQLiteDB) DeleteUser(username string, password string) {

	deleteUserSQL := `DELETE FROM users WHERE username = ? AND password = ?`
	_, err := s.db.Exec(deleteUserSQL, username, password)
	if err != nil {
		log.Fatal(err)
	}
}
