package pkg

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}
type Token interface {
	GenerateJWT(username, role string, sub uuid.UUID) (string, string, error)
	ValidateJWT(tokenString string) (*Claims, error)
}

type JWT struct {
	jwtSecret []byte
}

func NewJWT() (*JWT, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil, fmt.Errorf("JWT_SECRET not defined")
	}

	return &JWT{
		jwtSecret: []byte(secret),
	}, nil
}

func (j *JWT) GenerateJWT(username, role string, sub uuid.UUID) (string, string, error) {
	// Valid for 5 mins
	accessClaims := Claims{
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 5)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   sub.String(),
		},
	}

	// Valid for 1 day
	refreshClaims := Claims{
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   sub.String(),
		},
	}

	accessToken, err := j.generateToken(accessClaims)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := j.generateToken(refreshClaims)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (j *JWT) ValidateJWT(tokenString string) (*Claims, error) {
	token, claims, err := j.parseJWT(tokenString)

	if err != nil || !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}

	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, jwt.ErrTokenExpired
	}

	return claims, nil
}

func (j *JWT) generateToken(claims Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(j.jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (j *JWT) parseJWT(tokenString string) (*jwt.Token, *Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		return j.jwtSecret, nil
	})

	return token, claims, err
}
