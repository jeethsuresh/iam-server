package handlers

import (
	"net/http"

	"github.com/jeethsuresh/iam/auth"
	"github.com/labstack/echo/v4"
)

// RegisterUser creates an account from form POST.
func (h *Handlers) RegisterUser(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	if !RequireFormCredentials(c, username, password) {
		return nil
	}
	if err := h.DB.CreateUser(username, password); err != nil {
		return c.JSON(http.StatusBadRequest, err.Error())
	}
	return c.JSON(http.StatusOK, "User registered successfully.")
}

// Login authenticates a user. With sessionID, completes the federated flow after password check.
func (h *Handlers) Login(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	sessionID := c.FormValue("sessionID")

	if sessionID != "" {
		if !RequireFormCredentials(c, username, password) {
			return nil
		}
		if !h.DB.GetUser(username, password) {
			return c.JSON(http.StatusUnauthorized, "Invalid credentials.")
		}
		return auth.HandleSession(c, username, sessionID)
	}

	if !RequireFormCredentials(c, username, password) {
		return nil
	}
	if !h.DB.GetUser(username, password) {
		return c.JSON(http.StatusUnauthorized, "Invalid credentials.")
	}

	token, err := auth.GenerateToken(username)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Could not generate token.")
	}
	return c.JSON(http.StatusOK, map[string]string{"token": token})
}

// Logout acknowledges client-side token discard.
func (h *Handlers) Logout(c echo.Context) error {
	return c.JSON(http.StatusOK, "Logged out")
}

// BackendRegister starts a federated login session (JSON body).
func (h *Handlers) BackendRegister(c echo.Context) error {
	return auth.HandleBackend(c)
}
