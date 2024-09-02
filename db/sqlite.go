package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteDB struct {
	db *sql.DB
}

func NewSQLiteDB() (*SQLiteDB, error) {

	flag := false
	if _, err := os.Stat("./user_data.db"); err != nil {
		if os.IsNotExist(err) {
			flag = true
		}
	}

	db, err := sql.Open("sqlite3", "./user_data.db")
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	dbInstance := SQLiteDB{db: db}

	if flag {
		seedSQLiteDB(db)
	}

	return &dbInstance, nil
}

func seedSQLiteDB(db *sql.DB) {

	// Create the table if it does not exist
	createTableSQL := `CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL, 
		salt TEXT NOT NULL
	);`
	_, err := db.Exec(createTableSQL)
	if err != nil {
		log.Printf("Error creating table: %v", err)
	}

	// Insert sample data
	username := "user@localhost:8080"
	password := "password"

	insertUserSQL := `INSERT INTO users (id, username, password) VALUES (?, ?, ?)`
	_, err = db.Exec(insertUserSQL, 1, username, password)
	if err != nil {
		log.Printf("Error inserting data: %v", err)
	}
}

// CreateUser creates a new user in the database

func (s *SQLiteDB) CreateUser(username string, password string) error {
	// Generate the salt and hash the password
	salt, err := generateSalt(16)
	if err != nil {
		return err
	}
	hashedPassword, err := hashPassword(password, salt, PEPPER)
	if err != nil {
		return err
	}

	insertUserSQL := `INSERT INTO users (username, password) VALUES (?, ?)`
	_, err = s.db.Exec(insertUserSQL, username, hashedPassword)
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
		log.Printf("Error querying database: %v", err)
	}
	defer rows.Close()
	// Check if any rows were returned
	if !rows.Next() {
		return false
	}
	// Retrieve the first row
	var salt string
	if err := rows.Scan(&username, &password, &salt); err != nil {
		log.Printf("Error scanning row: %v", err)
		return false
	}

	// Verify the stored hashed password with the provided password
	return verifyPassword(password, password, salt, PEPPER)

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
