package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

func TestGenerateTokenRoundTrip(t *testing.T) {
	tok, err := GenerateToken("alice")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseWithClaims(tok, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, jwt.ErrSignatureInvalid
		}
		return JWTSecret, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := parsed.Claims.(*Claims)
	if claims.Username != "alice" {
		t.Fatalf("username %q", claims.Username)
	}
}

func TestGenerateTokenWithPrivateKeyRoundTrip(t *testing.T) {
	key, err := generatePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := generateTokenWithPrivateKey("bob", key, "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseWithClaims(tok, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodES256.Alg() {
			return nil, jwt.ErrSignatureInvalid
		}
		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := parsed.Claims.(*Claims)
	if claims.Username != "bob" || claims.SessionID != "sess-1" {
		t.Fatalf("claims %+v", claims)
	}
}

func TestHandleBackend_JSON(t *testing.T) {
	ResetSessions()
	t.Setenv("IAM_RELAXED_CALLBACK_URLS", "")
	t.Cleanup(func() { t.Setenv("IAM_RELAXED_CALLBACK_URLS", "") })

	e := echo.New()
	body := `{"username":"appuser","tokenURL":"https://1.1.1.1/token","redirectURL":"https://1.1.1.1/ok"}`
	req := httptest.NewRequest(http.MethodPost, "/backend/register", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := HandleBackend(c); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["sessionID"] == "" || out["publicKey"] == "" || out["username"] != "appuser" {
		t.Fatalf("response %#v", out)
	}
}

func TestHandleBackend_ValidationErrors(t *testing.T) {
	ResetSessions()
	t.Setenv("IAM_RELAXED_CALLBACK_URLS", "")
	e := echo.New()

	cases := []struct {
		name string
		body string
		code int
	}{
		{"empty body", "", http.StatusBadRequest},
		{"invalid json", "{", http.StatusBadRequest},
		{"missing username", `{"tokenURL":"https://1.1.1.1/t","redirectURL":"https://1.1.1.1/r"}`, http.StatusBadRequest},
		{"missing tokenURL", `{"username":"u","redirectURL":"https://1.1.1.1/r"}`, http.StatusBadRequest},
		{"missing redirectURL", `{"username":"u","tokenURL":"https://1.1.1.1/t"}`, http.StatusBadRequest},
		{"metadata tokenURL", `{"username":"u","tokenURL":"http://169.254.169.254/","redirectURL":"https://1.1.1.1/r"}`, http.StatusBadRequest},
		{"javascript redirect", `{"username":"u","tokenURL":"https://1.1.1.1/t","redirectURL":"javascript:alert(1)"}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/backend/register", strings.NewReader(tc.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			_ = HandleBackend(c)
			if rec.Code != tc.code {
				t.Fatalf("want %d got %d: %s", tc.code, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestHandleSession_Flow(t *testing.T) {
	ResetSessions()
	t.Setenv("IAM_RELAXED_CALLBACK_URLS", "1")
	t.Cleanup(func() {
		ResetSessions()
		t.Setenv("IAM_RELAXED_CALLBACK_URLS", "")
	})

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
		b, _ := io.ReadAll(r.Body)
		var payload map[string]interface{}
		if err := json.Unmarshal(b, &payload); err != nil {
			t.Errorf("json: %v", err)
		}
		if payload["sessionID"] == nil || payload["token"] == nil {
			t.Errorf("payload %s", string(b))
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(tokenSrv.Close)

	key, err := generatePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	sid := "test-session-id"
	sessions[sid] = SessionMapValue{
		Username:    "charlie",
		RedirectURL: "http://127.0.0.1:9999/final",
		TokenURL:    tokenSrv.URL + "/consume",
		PrivateKey:  key,
	}

	e := echo.New()
	form := "username=charlie&password=irrelevant&sessionID=" + sid
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := HandleSession(c, "charlie", sid); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out["redirect"], "sessionID=test-session-id") {
		t.Fatalf("redirect %q", out["redirect"])
	}
}

func TestHandleSession_Errors(t *testing.T) {
	ResetSessions()
	t.Cleanup(ResetSessions)
	t.Setenv("IAM_RELAXED_CALLBACK_URLS", "1")

	e := echo.New()
	t.Run("unknown session", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), rec)
		_ = HandleSession(c, "u", "nope")
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("got %d", rec.Code)
		}
	})

	key, _ := generatePrivateKey()
	sid := "s1"
	sessions[sid] = SessionMapValue{
		Username:    "victim",
		TokenURL:    "http://127.0.0.1:1/nope",
		RedirectURL: "http://127.0.0.1:2/ok",
		PrivateKey:  key,
	}

	t.Run("username mismatch", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), rec)
		_ = HandleSession(c, "other", sid)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("got %d", rec.Code)
		}
	})

	t.Run("token endpoint non-200", func(t *testing.T) {
		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}))
		t.Cleanup(bad.Close)
		sessions[sid] = SessionMapValue{
			Username:    "victim",
			TokenURL:    bad.URL,
			RedirectURL: "http://127.0.0.1:9/r",
			PrivateKey:  key,
		}
		rec := httptest.NewRecorder()
		c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), rec)
		_ = HandleSession(c, "victim", sid)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("got %d", rec.Code)
		}
	})
}

func TestHandleSession_BlocksMetadataURL(t *testing.T) {
	ResetSessions()
	t.Cleanup(ResetSessions)
	t.Setenv("IAM_RELAXED_CALLBACK_URLS", "1")

	key, _ := generatePrivateKey()
	sid := "meta"
	sessions[sid] = SessionMapValue{
		Username:    "u",
		TokenURL:    "http://127.0.0.1:9/ok",
		RedirectURL: "http://169.254.169.254/",
		PrivateKey:  key,
	}
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), rec)
	_ = HandleSession(c, "u", sid)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestResetSessions(t *testing.T) {
	key, _ := generatePrivateKey()
	sessions["x"] = SessionMapValue{Username: "a", PrivateKey: key}
	ResetSessions()
	if len(sessions) != 0 {
		t.Fatal("sessions not empty")
	}
}
