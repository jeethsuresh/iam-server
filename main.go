package main

import (
	"html/template"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/jeethsuresh/iam/auth"
	"github.com/jeethsuresh/iam/db"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// User stores user information
type User struct {
	Username string
	Password string
}

// Middleware to check JWT token
func authMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := c.Request().Header.Get("Authorization")

		if token == "" {
			return c.JSON(http.StatusUnauthorized, "Missing token")
		}
		token = token[len("Bearer "):] // Remove "Bearer " prefix

		claims := &auth.Claims{}
		_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			return auth.JWTSecret, nil
		})
		if err != nil {
			return c.JSON(http.StatusUnauthorized, "Invalid token: "+err.Error())
		}
		c.Set("username", claims.Username)
		return next(c)
	}
}

func main() {
	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{echo.GET, echo.HEAD, echo.PUT, echo.PATCH, echo.POST, echo.DELETE},
	}))

	db := db.NewDB()

	e.GET("/", func(c echo.Context) error {
		if c.Request().Header.Get("Authorization") != "" {
			return c.Redirect(http.StatusSeeOther, "/profile")
		}
		sessionID := c.QueryParam("sessionID")
		username := c.QueryParam("username")

		return renderTemplate(c, "login.html", map[string]string{
			"username":  username,
			"sessionID": sessionID,
		})
	})

	e.GET("/register", func(c echo.Context) error {
		return renderTemplate(c, "register.html", nil)
	})

	e.POST("/register", func(c echo.Context) error {
		username := c.FormValue("username")
		password := c.FormValue("password")

		if err := db.CreateUser(username, password); err != nil {
			return c.JSON(http.StatusBadRequest, err.Error())
		}

		return c.JSON(http.StatusOK, "User registered successfully.")
	})

	e.POST("/login", func(c echo.Context) error {
		username := c.FormValue("username")
		password := c.FormValue("password")
		sessionID := c.FormValue("sessionID")

		if sessionID != "" {
			return auth.HandleSession(c, username, sessionID)
		}

		exists := db.GetUser(username, password)
		if !exists {
			return c.JSON(http.StatusUnauthorized, "Invalid credentials.")
		}

		token, err := auth.GenerateToken(username)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, "Could not generate token.")
		}

		return c.JSON(http.StatusOK, map[string]string{"token": token})
	})

	e.GET("/profile", authMiddleware(func(c echo.Context) error {
		username := c.Get("username").(string)
		return renderTemplate(c, "profile.html", map[string]string{"Username": username})
	}))

	e.GET("/logout", func(c echo.Context) error {
		// Invalidate the token on the client-side
		return c.JSON(http.StatusOK, "Logged out")
	})

	e.POST("/backend/register", func(c echo.Context) error {
		return auth.HandleBackend(c)
	})

	e.Logger.Fatal(e.Start(":8080"))
}

// Render templates
func renderTemplate(c echo.Context, name string, data interface{}) error {
	tmpl := template.Must(template.ParseFiles("templates/" + name))
	return tmpl.Execute(c.Response().Writer, data)
}
