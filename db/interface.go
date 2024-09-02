package db

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

type DB interface {
	CreateUser(username string, password string) error
	GetUser(username string, password string) bool
	DeleteUser(username string) error
}

const PEPPER = "pepperidge_farm_remembers"

func hashPassword(password string, salt, pepper string) (string, error) {
	pepperedPassword := password + salt + pepper
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(pepperedPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// Verifies the password by comparing it with the hashed password stored in the DB
func verifyPassword(hashedPassword string, password string, salt, pepper string) bool {
	pepperedPassword := password + salt + pepper
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(pepperedPassword))
	return err == nil
}

func generateSalt(size int) (string, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}
