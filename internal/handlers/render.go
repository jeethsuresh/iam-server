package handlers

import (
	"html/template"

	"github.com/labstack/echo/v4"
)

const templatesDir = "templates/"

// RenderHTML parses templates/<name> and writes to the response.
func RenderHTML(c echo.Context, name string, data interface{}) error {
	tmpl := template.Must(template.ParseFiles(templatesDir + name))
	return tmpl.Execute(c.Response().Writer, data)
}
