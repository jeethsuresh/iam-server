package db

import (
	"fmt"
	"os"
)

// OpenFromEnv returns a database implementation based on USE_POSTGRES or USE_SQLITE.
func OpenFromEnv() (DB, error) {
	if os.Getenv("USE_POSTGRES") != "" {
		user := os.Getenv("POSTGRES_USER")
		pass := os.Getenv("POSTGRES_PASSWORD")
		host := os.Getenv("POSTGRES_URL")
		fmt.Printf("Connecting to Postgres at %s\n", host)
		return NewPostgresDB(user, pass, host)
	}
	if os.Getenv("USE_SQLITE") != "" {
		return NewSQLiteDB()
	}
	return nil, fmt.Errorf("no database connection string provided")
}
