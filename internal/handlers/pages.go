package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// LoginPage serves the federated return URL (/?username=&sessionID=) or the normal login form.
func (h *Handlers) LoginPage(c echo.Context) error {
	if c.Request().Header.Get(echo.HeaderAuthorization) != "" {
		return c.Redirect(http.StatusSeeOther, "/profile")
	}
	return RenderHTML(c, "login.html", map[string]string{
		"username":  c.QueryParam("username"),
		"sessionID": c.QueryParam("sessionID"),
	})
}

// RegisterPage serves the self-service registration form.
func (h *Handlers) RegisterPage(c echo.Context) error {
	return RenderHTML(c, "register.html", nil)
}

// ProfilePage serves the authenticated profile (username set by JWT middleware).
func (h *Handlers) ProfilePage(c echo.Context) error {
	username := c.Get("username").(string)
	return RenderHTML(c, "profile.html", map[string]string{"Username": username})
}
