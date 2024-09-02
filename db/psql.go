package db

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

// PostgreSQL implementation of the DB interface
type PostgresDB struct {
	conn *sql.DB
}

// CreateUser inserts a new user with a hashed password into the database
func (db *PostgresDB) CreateUser(username string, password string) error {
	// Hash the password with pepper

	// Generate the salt and hash the password
	salt, err := generateSalt(16)
	if err != nil {
		return err
	}
	hashedPassword, err := hashPassword(password, salt, PEPPER)
	if err != nil {
		return err
	}

	// Insert the user into the PostgreSQL database
	query := `INSERT INTO users (username, password, salt) VALUES ($1, $2, $3)`
	_, err = db.conn.Exec(query, username, hashedPassword, salt)
	if err != nil {
		return fmt.Errorf("failed to create user: %v", err)
	}

	fmt.Println("User created successfully.")
	return nil
}

// GetUser validates the username and password
func (db *PostgresDB) GetUser(username string, password string) bool {
	var storedHash, storedSalt string

	// Query the user's hashed password from the database
	query := `SELECT password, salt FROM users WHERE username = $1`
	err := db.conn.QueryRow(query, username).Scan(&storedHash, &storedSalt)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("User not found: %s", username)
			return false
		}
		log.Printf("Failed to retrieve user: %v", err)
		return false
	}

	// Verify the stored hashed password with the provided password
	return verifyPassword(storedHash, password, storedSalt, PEPPER)
}

// DeleteUser removes a user from the database
func (db *PostgresDB) DeleteUser(username string) error {
	// Delete the user from the database
	query := `DELETE FROM users WHERE username = $1`
	_, err := db.conn.Exec(query, username)
	if err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}

	fmt.Println("User deleted successfully.")
	return nil
}

// NewPostgresDB initializes a new PostgresDB connection
func NewPostgresDB(username, password, url string) (*PostgresDB, error) {
	// Create the connection string
	connectionString := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", url, "5432", username, password, "app")
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, err
	}

	// Ensure the connection is valid
	if err = db.Ping(); err != nil {
		return nil, err
	}

	seedPostgresDB(db)

	return &PostgresDB{conn: db}, nil
}

func seedPostgresDB(db *sql.DB) {

	// check if table exists
	var exists bool
	err := db.QueryRow("SELECT EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'users')").Scan(&exists)
	if err != nil {
		log.Printf("Error checking if table exists: %v", err)
	}
	if exists {
		return
	}

	// Create the table if it does not exist
	createTableSQL := `CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		salt TEXT NOT NULL
	);`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Printf("Error creating table: %v", err)
	}

	// Insert sample data
	username := "user@localhost:8080"
	password := "password"

	insertUserSQL := `INSERT INTO users (username, password) VALUES ($1, $2)`
	_, err = db.Exec(insertUserSQL, username, password)
	if err != nil {
		log.Printf("Error inserting data: %v", err)
	}
}
