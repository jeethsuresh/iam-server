package handlers

import (
	"strings"

	"github.com/labstack/echo/v4"
)

// Limits for form credentials (defense in depth; DB column limits may differ).
const (
	MaxUsernameLen = 256
	MaxPasswordLen = 1024
)

// RequireFormCredentials rejects empty/whitespace-only username or password, or overlong values.
// On failure it writes JSON 400 and returns false.
func RequireFormCredentials(c echo.Context, username, password string) bool {
	if strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		_ = c.JSON(400, "username and password are required")
		return false
	}
	if len(username) > MaxUsernameLen || len(password) > MaxPasswordLen {
		_ = c.JSON(400, "username or password too long")
		return false
	}
	return true
}
