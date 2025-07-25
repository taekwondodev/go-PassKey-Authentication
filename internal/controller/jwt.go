package controller

import (
	"encoding/json"

	"github.com/taekwondodev/go-PassKey-Authentication/internal/customerrors"

	"net/http"

	"github.com/taekwondodev/go-PassKey-Authentication/internal/dto"
)

func (c *controller) Refresh(w http.ResponseWriter, r *http.Request) error {
	var req dto.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return customerrors.ErrBadRequest
	}

	res, err := c.authService.Refresh(req)
	if err != nil {
		return err
	}

	return c.respond(w, http.StatusOK, res)
}
