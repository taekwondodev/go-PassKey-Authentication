package customerrors

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

var (
	ErrUsernameAlreadyExists = &Error{Code: 409, Message: "username already exists"}
	ErrSessionIdInvalid      = &Error{Code: 401, Message: "session id not valid"}
	ErrInvalidCredentials    = &Error{Code: 401, Message: "invalid credentials"}
	ErrSessionNotFound       = &Error{Code: 404, Message: "session not found"}
	ErrUserNotFound          = &Error{Code: 404, Message: "user not found"}
	ErrBadRequest            = &Error{Code: 400, Message: "bad request"}
	ErrInvalidUsername       = &Error{Code: 400, Message: "invalid username"}
	ErrInvalidAAGUID         = &Error{Code: 400, Message: "invalid aaguid"}
	ErrInternalServer        = &Error{Code: 500, Message: "internal server error"}
)

func GetStatus(err error) int {
	if customErr, ok := err.(*Error); ok {
		return customErr.Code
	}

	switch err {
	case jwt.ErrSignatureInvalid, jwt.ErrTokenExpired:
		return 401

	default:
		return 500
	}
}

func GetMessage(err error) string {
	if customErr, ok := err.(*Error); ok {
		return customErr.Message
	} else {
		return err.Error()
	}
}
