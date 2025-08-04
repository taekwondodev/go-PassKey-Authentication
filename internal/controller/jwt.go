package controller

import (
	"net/http"

	"github.com/taekwondodev/go-PassKey-Authentication/internal/customerrors"
)

func (c *controller) Refresh(w http.ResponseWriter, r *http.Request) error {
	refreshToken, err := c.tokenCookie.GetRefreshTokenFromCookie(r)
	if err != nil {
		return customerrors.ErrBadRequest
	}

	res, newToken, err := c.authService.Refresh(r.Context(), refreshToken)
	if err != nil {
		return err
	}

	c.tokenCookie.SetRefreshTokenCookie(w, newToken)
	return c.respond(w, http.StatusOK, res)
}

func (c *controller) Logout(w http.ResponseWriter, r *http.Request) error {
	refreshToken, err := c.tokenCookie.GetRefreshTokenFromCookie(r)
	if err != nil {
		refreshToken = ""
	}

	res, err := c.authService.Logout(r.Context(), refreshToken)
	if err != nil {
		return err
	}

	c.tokenCookie.ClearRefreshTokenCookie(w)
	return c.respond(w, http.StatusOK, res)
}
