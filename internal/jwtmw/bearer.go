package jwtmw

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/jeethsuresh/iam/auth"
	"github.com/labstack/echo/v4"
)

const bearerPrefix = "Bearer "

// RequireHS256 accepts Authorization: Bearer <JWT> and requires HS256 signed with auth.JWTSecret.
// On success, sets echo context key "username" to the claim value.
func RequireHS256() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			raw := c.Request().Header.Get(echo.HeaderAuthorization)
			if raw == "" {
				return c.JSON(http.StatusUnauthorized, "Missing token")
			}
			if !strings.HasPrefix(raw, bearerPrefix) {
				return c.JSON(http.StatusUnauthorized, "Missing or invalid Authorization scheme")
			}
			tokenStr := strings.TrimPrefix(raw, bearerPrefix)
			if tokenStr == "" {
				return c.JSON(http.StatusUnauthorized, "Missing token")
			}

			claims := &auth.Claims{}
			_, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
				if m, ok := token.Method.(*jwt.SigningMethodHMAC); !ok || m.Alg() != jwt.SigningMethodHS256.Alg() {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return auth.JWTSecret, nil
			})
			if err != nil {
				return c.JSON(http.StatusUnauthorized, "Invalid token")
			}
			c.Set("username", claims.Username)
			return next(c)
		}
	}
}
