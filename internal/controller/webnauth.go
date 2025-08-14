package controller

import (
	"encoding/json/v2"
	"net/http"

	"github.com/taekwondodev/go-PassKey-Authentication/internal/customerrors"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/dto"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/service"
	"github.com/taekwondodev/go-PassKey-Authentication/pkg"
)

type AuthController interface {
	BeginRegister(w http.ResponseWriter, r *http.Request) error
	FinishRegister(w http.ResponseWriter, r *http.Request) error
	BeginLogin(w http.ResponseWriter, r *http.Request) error
	FinishLogin(w http.ResponseWriter, r *http.Request) error
	Refresh(w http.ResponseWriter, r *http.Request) error
	Logout(w http.ResponseWriter, r *http.Request) error
}

type controller struct {
	authService service.AuthService
	tokenCookie pkg.CookieHelper
}

func New(authService service.AuthService, tokenCookie pkg.CookieHelper) AuthController {
	return &controller{
		authService: authService,
		tokenCookie: tokenCookie,
	}
}

type Validator interface {
	Validate() error
}

func (c *controller) BeginRegister(w http.ResponseWriter, r *http.Request) error {
	req, err := decodeAndValidate[*dto.BeginRequest](r)
	if err != nil {
		return err
	}

	res, err := c.authService.BeginRegister(r.Context(), req.Username, req.Role)
	if err != nil {
		return err
	}

	return c.respond(w, http.StatusAccepted, res)
}

func (c *controller) FinishRegister(w http.ResponseWriter, r *http.Request) error {
	req, err := decodeAndValidate[*dto.FinishRequest](r)
	if err != nil {
		return err
	}

	res, err := c.authService.FinishRegister(r.Context(), req)
	if err != nil {
		return err
	}

	return c.respond(w, http.StatusCreated, res)
}

func (c *controller) BeginLogin(w http.ResponseWriter, r *http.Request) error {
	req, err := decodeAndValidate[*dto.BeginRequest](r)
	if err != nil {
		return err
	}

	res, err := c.authService.BeginLogin(r.Context(), req.Username)
	if err != nil {
		return err
	}

	return c.respond(w, http.StatusAccepted, res)
}

func (c *controller) FinishLogin(w http.ResponseWriter, r *http.Request) error {
	req, err := decodeAndValidate[*dto.FinishRequest](r)
	if err != nil {
		return err
	}

	res, newToken, err := c.authService.FinishLogin(r.Context(), req)
	if err != nil {
		return err
	}

	c.tokenCookie.SetRefreshTokenCookie(w, newToken)
	return c.respond(w, http.StatusOK, res)
}

func decodeAndValidate[T Validator](r *http.Request) (T, error) {
	defer r.Body.Close()
	var req T

	if err := json.UnmarshalRead(r.Body, &req, json.RejectUnknownMembers(true)); err != nil {
		return req, customerrors.ErrBadRequest
	}

	if err := req.Validate(); err != nil {
		return req, err
	}

	return req, nil
}

func (c *controller) respond(w http.ResponseWriter, status int, data any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.MarshalWrite(w, data)
}
