package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// var users = make(map[string]User)
var JWTSecret = []byte("your-secret-key") // Replace with a strong secret key

// Token claims structure
type Claims struct {
	Username  string `json:"username"`
	SessionID string `json:"sessionID"`
	jwt.StandardClaims
}

var sessions = map[string]SessionMapValue{}

type SessionMapValue struct {
	Username    string            `json:"username"`
	RedirectURL string            `json:"redirectURL"`
	TokenURL    string            `json:"tokenURL"`
	PrivateKey  *ecdsa.PrivateKey `json:"privateKey"`
}

// Generate a new JWT token
func GenerateToken(username string) (string, error) {
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(), // Token expires in 1 hour
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JWTSecret)
}

func generatePrivateKey() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("error generating private key: %v", err)
	}
	return privateKey, nil
}

func generateTokenWithPrivateKey(username string, privateKey *ecdsa.PrivateKey, sessionID string) (string, error) {
	claims := &Claims{
		Username:  username,
		SessionID: sessionID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(), // Token expires in 1 hour
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(privateKey)
}

func HandleSession(c echo.Context, username string, sessionID string) error {
	var currSession SessionMapValue
	var ok bool
	if currSession, ok = sessions[sessionID]; !ok {
		return c.JSON(http.StatusInternalServerError, "Session ID does not exist.")

	}
	if currSession.Username != username {
		return c.JSON(http.StatusUnauthorized, "Invalid session ID.")
	}

	type BackendRequest struct {
		SessionID string `json:"sessionID"`
		Token     string `json:"token"`
	}

	encryptedToken, err := generateTokenWithPrivateKey(username, currSession.PrivateKey, sessionID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Could not encrypt token: "+err.Error())
	}

	body := BackendRequest{sessionID, encryptedToken}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Could not marshal request.")
	}
	fmt.Printf("***** %+v\n", string(jsonBody))
	req, err := http.NewRequest("POST", currSession.TokenURL, bytes.NewBuffer(jsonBody))
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
	fullRedirectURL, errURL := url.Parse(currSession.RedirectURL)
	if errURL != nil {
		return c.JSON(http.StatusInternalServerError, "Could not parse redirect URL.")
	}
	fullRedirectURLQuery := fullRedirectURL.Query()
	fullRedirectURLQuery.Add("sessionID", sessionID)
	fullRedirectURL.RawQuery = fullRedirectURLQuery.Encode()
	return c.JSON(http.StatusOK, map[string]string{"redirect": fullRedirectURL.String()})

}

func HandleBackend(c echo.Context) error {

	privateKey, err := generatePrivateKey()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Could not generate private key: "+err.Error())
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	publicKeyBase64 := base64.StdEncoding.EncodeToString(pubBytes)

	user := SessionMapValue{}
	if err := c.Bind(&user); err != nil {
		fmt.Printf("***** err: %+v\n", err)
		return c.JSON(http.StatusBadRequest, err.Error())
	}
	sessionID := uuid.New().String()
	if user.Username == "" {
		return c.JSON(http.StatusBadRequest, "Invalid username")
	}
	user.PrivateKey = privateKey
	sessions[sessionID] = user

	return c.JSON(http.StatusOK, map[string]string{"sessionID": sessionID, "username": user.Username, "publicKey": publicKeyBase64})
}
