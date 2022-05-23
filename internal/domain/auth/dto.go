package auth

import (
	"auth-jwt-server/pkg/input_validator"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"os"
)

type RegisterRequestDTO struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,gte=6"`
}

func (r *RegisterRequestDTO) Validate() []string {
	return input_validator.NewInputValidator().Validate(r)
}

type RegisterResponseDTO struct {
	UserId       int    `json:"user_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type VerifyResponseDTO struct {
	UserId     int  `json:"user_id"`
	IsVerified bool `json:"is_verified"`
}

type LoginRequestDTO struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,gte=6"`
}

func (r *LoginRequestDTO) Validate() []string {
	return input_validator.NewInputValidator().Validate(r)
}

type LoginResponseDTO struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type RefreshTokenRequestDTO struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (r *RefreshTokenRequestDTO) IsAccessTokenValid() *jwt.ValidationError {

	// 1. invalid token.
	// 2. valid token but expired
	_, err := jwt.Parse(r.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("TOKEN_SECRET")), nil
	})
	if err != nil {
		var vErr *jwt.ValidationError
		if errors.As(err, &vErr) {
			return vErr
		}
	}
	return nil
}
