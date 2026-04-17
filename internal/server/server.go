package server

import (
	"github.com/jeethsuresh/iam/db"
	"github.com/jeethsuresh/iam/internal/handlers"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// New builds an Echo app with default middleware and all IAM routes.
func New(database db.DB) *echo.Echo {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{echo.GET, echo.HEAD, echo.PUT, echo.PATCH, echo.POST, echo.DELETE},
	}))
	AttachRoutes(e, database)
	return e
}

// AttachRoutes wires application handlers (used by New and by tests that build Echo without default middleware).
func AttachRoutes(e *echo.Echo, database db.DB) {
	handlers.New(database).Register(e)
}
