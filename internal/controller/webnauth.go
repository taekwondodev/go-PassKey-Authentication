package controller

import (
	"encoding/json"
	"go-PassKey-Authentication/internal/customerrors"
	"go-PassKey-Authentication/internal/dto"
	"go-PassKey-Authentication/internal/service"
	"net/http"
)

type AuthController interface {
	BeginRegister(w http.ResponseWriter, r *http.Request) error
	FinishRegister(w http.ResponseWriter, r *http.Request) error
	BeginLogin(w http.ResponseWriter, r *http.Request) error
	FinishLogin(w http.ResponseWriter, r *http.Request) error
	Refresh(w http.ResponseWriter, r *http.Request) error
}

type controller struct {
	authService service.AuthService
}

func New(authService service.AuthService) AuthController {
	return &controller{authService: authService}
}

// da cambiaro con encoding/jsonv2

func (c *controller) BeginRegister(w http.ResponseWriter, r *http.Request) error {
	var req dto.BeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return customerrors.ErrBadRequest
	}

	res, err := c.authService.BeginRegister(r.Context(), req.Username, req.Role)
	if err != nil {
		return err
	}

	return c.respond(w, http.StatusAccepted, res)
}

func (c *controller) FinishRegister(w http.ResponseWriter, r *http.Request) error {
	var req dto.FinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return customerrors.ErrBadRequest
	}

	res, err := c.authService.FinishRegister(r.Context(), req)
	if err != nil {
		return err
	}

	return c.respond(w, http.StatusCreated, res)
}

func (c *controller) BeginLogin(w http.ResponseWriter, r *http.Request) error {
	var req dto.BeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return customerrors.ErrBadRequest
	}

	res, err := c.authService.BeginLogin(r.Context(), req.Username)
	if err != nil {
		return err
	}

	return c.respond(w, http.StatusAccepted, res)
}

func (c *controller) FinishLogin(w http.ResponseWriter, r *http.Request) error {
	var req dto.FinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return customerrors.ErrBadRequest
	}

	res, err := c.authService.FinishLogin(r.Context(), req)
	if err != nil {
		return err
	}

	return c.respond(w, http.StatusOK, res)
}

func (c *controller) respond(w http.ResponseWriter, status int, data any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}
