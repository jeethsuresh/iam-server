package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/jeethsuresh/iam/db"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// User stores user information
type User struct {
	Username string
	Password string
}

// var users = make(map[string]User)
var jwtSecret = []byte("your-secret-key") // Replace with a strong secret key

// Token claims structure
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// Generate a new JWT token
func generateToken(username string) (string, error) {
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(), // Token expires in 1 hour
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// Middleware to check JWT token
func authMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := c.Request().Header.Get("Authorization")

		if token == "" {
			return c.JSON(http.StatusUnauthorized, "Missing token")
		}
		token = token[len("Bearer "):] // Remove "Bearer " prefix

		claims := &Claims{}
		_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil {
			return c.JSON(http.StatusUnauthorized, "Invalid token: "+err.Error())
		}
		c.Set("username", claims.Username)
		return next(c)
	}
}

var sessions = map[string]string{}

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
		fmt.Printf("******* sessionID: %s, username: %s\n", sessionID, username)
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

		exists := db.GetUser(username, password)
		if !exists {
			return c.JSON(http.StatusUnauthorized, "Invalid credentials.")
		}

		token, err := generateToken(username)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, "Could not generate token.")
		}
		fmt.Printf("***** %+v\n", sessionID)
		if sessionID != "" {
			if _, ok := sessions[sessionID]; ok {
				if sessions[sessionID] != username {
					return c.JSON(http.StatusUnauthorized, "Invalid session ID.")
				} else {
					type BackendRequest struct {
						SessionID string `json:"sessionID"`
						Token     string `json:"token"`
					}
					body := BackendRequest{sessionID, "your-generated-auth-token"}
					fmt.Printf("***** %+v\n", body)
					jsonBody, err := json.Marshal(body)
					if err != nil {
						return c.JSON(http.StatusInternalServerError, "Could not marshal request.")
					}
					req, err := http.NewRequest("POST", "http://localhost:5173/login/setToken", bytes.NewBuffer(jsonBody))
					if err != nil {
						return c.JSON(http.StatusInternalServerError, "Could not create request.")
					}
					req.Header.Set("Content-Type", "application/json")
					client := &http.Client{Timeout: 10 * time.Second}
					resp, err := client.Do(req)
					if err != nil {
						return c.JSON(http.StatusInternalServerError, "Could not send request.")
					}
					defer resp.Body.Close()

					if resp.StatusCode != http.StatusOK {
						return c.JSON(http.StatusInternalServerError, "Could not validate session ID: "+resp.Status)
					}
					return c.JSON(http.StatusOK, map[string]string{"redirect": "http://localhost:5173/login/backend?sessionID=" + sessionID})
				}
			}
		}
		fmt.Printf("***** Generated token: %+v\n", token)

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
		var user struct {
			Username string `json:"username"`
		}
		if err := c.Bind(&user); err != nil {
			return c.JSON(http.StatusBadRequest, err.Error())
		}
		sessionID := uuid.New().String()
		if user.Username == "" {
			return c.JSON(http.StatusBadRequest, "Invalid username")
		}
		sessions[sessionID] = user.Username

		return c.JSON(http.StatusOK, map[string]string{"sessionID": sessionID})
	})

	e.Logger.Fatal(e.Start(":8080"))
}

// Render templates
func renderTemplate(c echo.Context, name string, data interface{}) error {
	tmpl := template.Must(template.ParseFiles("templates/" + name))
	return tmpl.Execute(c.Response().Writer, data)
}
