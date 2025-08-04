package controller

import (
	"net/http"

	"github.com/taekwondodev/go-PassKey-Authentication/internal/dto"
)

func (c *controller) Refresh(w http.ResponseWriter, r *http.Request) error {
	req, err := decodeAndValidate[*dto.TokenRequest](r)
	if err != nil {
		return err
	}

	res, err := c.authService.Refresh(r.Context(), *req)
	if err != nil {
		return err
	}

	return c.respond(w, http.StatusOK, res)
}

func (c *controller) Logout(w http.ResponseWriter, r *http.Request) error {
	req, err := decodeAndValidate[*dto.TokenRequest](r)
	if err != nil {
		return err
	}

	res, err := c.authService.Logout(r.Context(), *req)
	if err != nil {
		return err
	}

	return c.respond(w, http.StatusOK, res)
}
