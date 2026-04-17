package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/jeethsuresh/iam/auth"
	"github.com/jeethsuresh/iam/db"
	"github.com/jeethsuresh/iam/internal/handlers"
	"github.com/jeethsuresh/iam/internal/server"
	"github.com/labstack/echo/v4"
)

func testEcho(t *testing.T, provider db.DB) *echo.Echo {
	t.Helper()
	e := echo.New()
	server.AttachRoutes(e, provider)
	return e
}

func testSQLite(t *testing.T) *db.SQLiteDB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	sdb, err := db.NewSQLiteDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sdb.Close() })
	if err := sdb.TruncateUsers(); err != nil {
		t.Fatal(err)
	}
	return sdb
}

func TestAttachRoutes_RegisterLoginProfile(t *testing.T) {
	sdb := testSQLite(t)
	e := testEcho(t, sdb)

	reg := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("username=u1&password=secret"))
	reg.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, reg)
	if rec.Code != http.StatusOK {
		t.Fatalf("register %d %s", rec.Code, rec.Body.String())
	}

	login := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=u1&password=secret"))
	login.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, login)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	tok := out["token"]
	if tok == "" {
		t.Fatal("no token")
	}

	req := httptest.NewRequest(http.MethodGet, "/profile", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+tok)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("profile %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "u1") {
		t.Fatal("profile body missing username")
	}
}

func TestAttachRoutes_RegisterDuplicate(t *testing.T) {
	sdb := testSQLite(t)
	e := testEcho(t, sdb)
	body := "username=dup&password=pw"
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if i == 0 && rec.Code != http.StatusOK {
			t.Fatalf("first register %d", rec.Code)
		}
		if i == 1 && rec.Code != http.StatusBadRequest {
			t.Fatalf("duplicate want 400 got %d %s", rec.Code, rec.Body.String())
		}
	}
}

func TestAttachRoutes_LoginWrongPassword(t *testing.T) {
	sdb := testSQLite(t)
	e := testEcho(t, sdb)
	reg := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("username=u&password=good"))
	reg.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	e.ServeHTTP(httptest.NewRecorder(), reg)

	login := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=u&password=bad"))
	login.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, login)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestAttachRoutes_ProfileAuth(t *testing.T) {
	sdb := testSQLite(t)
	e := testEcho(t, sdb)

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/profile", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth want 401 got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/profile", nil)
	req.Header.Set(echo.HeaderAuthorization, "not-bearer")
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad scheme %d", rec.Code)
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"username": "x",
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	signed, _ := tok.SignedString(auth.JWTSecret)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/profile", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+signed)
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("HS512 should be rejected, got %d", rec.Code)
	}
}

func TestAttachRoutes_CredentialValidation(t *testing.T) {
	sdb := testSQLite(t)
	e := testEcho(t, sdb)

	cases := []struct {
		path, body string
		code       int
	}{
		{"/register", "username=&password=x", http.StatusBadRequest},
		{"/register", "username=x&password=", http.StatusBadRequest},
		{"/login", "username=&password=x", http.StatusBadRequest},
		{"/login", "username=x&password=y", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != tc.code {
			t.Fatalf("%s %q want %d got %d %s", tc.path, tc.body, tc.code, rec.Code, rec.Body.String())
		}
	}

	longUser := strings.Repeat("a", handlers.MaxUsernameLen+1)
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("username="+longUser+"&password=x"))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("long username %d", rec.Code)
	}
}

func TestAttachRoutes_LogoutAndHome(t *testing.T) {
	sdb := testSQLite(t)
	e := testEcho(t, sdb)

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logout", nil))
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}

	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Login") {
		t.Fatalf("home %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer x")
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("redirect %d", rec.Code)
	}
	if loc := rec.Header().Get(echo.HeaderLocation); loc != "/profile" {
		t.Fatal(loc)
	}
}

func TestAttachRoutes_RegisterGet(t *testing.T) {
	sdb := testSQLite(t)
	e := testEcho(t, sdb)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/register", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Register") {
		t.Fatalf("register page: %d", rec.Code)
	}
}

func TestAttachRoutes_BackendRegister_RequiresPublicURLWithoutRelaxed(t *testing.T) {
	auth.ResetSessions()
	t.Cleanup(auth.ResetSessions)
	t.Setenv("IAM_RELAXED_CALLBACK_URLS", "")

	sdb := testSQLite(t)
	e := testEcho(t, sdb)

	br, _ := json.Marshal(map[string]string{
		"username":    "x",
		"tokenURL":    "http://127.0.0.1:9/t",
		"redirectURL": "https://1.1.1.1/r",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/backend/register", bytes.NewReader(br))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for loopback tokenURL, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestAttachRoutes_HomeQueryParamsReflected(t *testing.T) {
	sdb := testSQLite(t)
	e := testEcho(t, sdb)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/?username=u1&sessionID=sid", nil)
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `value="u1"`) || !strings.Contains(body, `value="sid"`) {
		t.Fatal("expected quoted reflected query params")
	}
}

func TestAttachRoutes_LongPasswordRejected(t *testing.T) {
	sdb := testSQLite(t)
	e := testEcho(t, sdb)
	pw := strings.Repeat("p", handlers.MaxPasswordLen+1)
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("username=u&password="+pw))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestAttachRoutes_FederatedLogin(t *testing.T) {
	auth.ResetSessions()
	t.Cleanup(auth.ResetSessions)
	t.Setenv("IAM_RELAXED_CALLBACK_URLS", "1")
	t.Cleanup(func() { t.Setenv("IAM_RELAXED_CALLBACK_URLS", "") })

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(tokenSrv.Close)

	sdb := testSQLite(t)
	e := testEcho(t, sdb)

	reg := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("username=fed&password=pw"))
	reg.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	e.ServeHTTP(httptest.NewRecorder(), reg)

	br, _ := json.Marshal(map[string]string{
		"username":    "fed",
		"tokenURL":    tokenSrv.URL + "/t",
		"redirectURL": "http://127.0.0.1:9/done",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/backend/register", bytes.NewReader(br))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("backend register %d %s", rec.Code, rec.Body.String())
	}
	var bout map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &bout); err != nil {
		t.Fatal(err)
	}
	sid := bout["sessionID"]

	rec = httptest.NewRecorder()
	login := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(
		"username=fed&password=pw&sessionID="+sid))
	login.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	e.ServeHTTP(rec, login)
	if rec.Code != http.StatusOK {
		t.Fatalf("federated login %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	badLogin := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(
		"username=fed&password=wrong&sessionID="+sid))
	badLogin.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	e.ServeHTTP(rec, badLogin)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password %d", rec.Code)
	}
}
