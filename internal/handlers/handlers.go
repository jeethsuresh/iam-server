package handlers

import (
	"github.com/jeethsuresh/iam/db"
	"github.com/jeethsuresh/iam/internal/jwtmw"
	"github.com/labstack/echo/v4"
)

// Handlers holds dependencies for HTTP handlers.
type Handlers struct {
	DB db.DB
}

// New returns route handlers backed by db.
func New(database db.DB) *Handlers {
	return &Handlers{DB: database}
}

// Register attaches all application routes to the Echo instance.
func (h *Handlers) Register(e *echo.Echo) {
	e.GET("/", h.LoginPage)
	e.GET("/register", h.RegisterPage)
	e.POST("/register", h.RegisterUser)
	e.POST("/login", h.Login)
	e.GET("/profile", h.ProfilePage, jwtmw.RequireHS256())
	e.GET("/logout", h.Logout)
	e.POST("/backend/register", h.BackendRegister)
}
