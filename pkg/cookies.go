package pkg

import (
	"net/http"
	"os"
	"strings"
	"time"
)

const RefreshTokenCookieName = "refresh_token"

type CookieConfig struct {
	Secure   bool
	SameSite http.SameSite
	Domain   string
	Path     string
	HttpOnly bool
	MaxAge   int
}

type CookieHelper interface {
	SetRefreshTokenCookie(w http.ResponseWriter, token string)
	GetRefreshTokenFromCookie(r *http.Request) (string, error)
	ClearRefreshTokenCookie(w http.ResponseWriter)
}

type CookieToken struct {
	Configs                *CookieConfig
	refreshTokenCookieName string
	expirationTokenCookie  time.Time
}

func NewCookieHelper() CookieHelper {
	origin := os.Getenv("ORIGIN")

	config := &CookieConfig{
		Secure:   false,                 // HTTP in development
		SameSite: http.SameSiteNoneMode, // Required for cross-origin cookies
		Domain:   "",                    // Empty for localhost
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400,
	}

	if strings.HasPrefix(origin, "https://") {
		config.Secure = true                      // Set to true in production with HTTPS
		config.SameSite = http.SameSiteStrictMode // Use strict mode for production
		config.Domain = strings.TrimPrefix(origin, "https://")
	} else if strings.Contains(origin, "localhost") {
		config.SameSite = http.SameSiteLaxMode // Use lax mode for localhost
	}

	expiration := time.Now().Add(24 * time.Hour)
	return &CookieToken{
		Configs:                config,
		refreshTokenCookieName: RefreshTokenCookieName,
		expirationTokenCookie:  expiration,
	}
}

func (c *CookieToken) SetRefreshTokenCookie(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:     c.refreshTokenCookieName,
		Value:    token,
		Path:     c.Configs.Path,
		Expires:  c.expirationTokenCookie,
		MaxAge:   c.Configs.MaxAge,
		HttpOnly: c.Configs.HttpOnly,
		Secure:   c.Configs.Secure,
		SameSite: c.Configs.SameSite,
	}

	if c.Configs.Domain != "" {
		cookie.Domain = c.Configs.Domain
	}

	http.SetCookie(w, cookie)
}

func (c *CookieToken) GetRefreshTokenFromCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(c.refreshTokenCookieName)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func (c *CookieToken) ClearRefreshTokenCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     c.refreshTokenCookieName,
		Value:    "",
		Path:     c.Configs.Path,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   c.Configs.Secure,
		SameSite: c.Configs.SameSite,
		MaxAge:   -1,
	}

	if c.Configs.Domain != "" {
		cookie.Domain = c.Configs.Domain
	}

	http.SetCookie(w, cookie)
}
