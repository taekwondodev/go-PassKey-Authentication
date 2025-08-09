package pkg

import (
	"net/http"
	"time"

	"github.com/taekwondodev/go-PassKey-Authentication/internal/config"
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
}

func NewCookieHelper() (CookieHelper, error) {
	originConfig, err := config.LoadOriginConfig()
	if err != nil {
		return nil, err
	}

	config := &CookieConfig{
		Secure:   originConfig.IsHTTPS,             // HTTP in development
		SameSite: originConfig.GetCookieSameSite(), // Required for cross-origin cookies
		Domain:   originConfig.Domain,              // Empty for localhost
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400,
	}

	return &CookieToken{
		Configs:                config,
		refreshTokenCookieName: RefreshTokenCookieName,
	}, nil
}

func (c *CookieToken) SetRefreshTokenCookie(w http.ResponseWriter, token string) {
	expiration := time.Now().Add(24 * time.Hour)
	cookie := &http.Cookie{
		Name:     c.refreshTokenCookieName,
		Value:    token,
		Path:     c.Configs.Path,
		Expires:  expiration,
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
