package auth

import (
	"auth-jwt-server/internal/domain/auth_token"
	"auth-jwt-server/internal/domain/user"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator/v10"
)

type RegisterRequestDTO struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

func (r *RegisterRequestDTO) Validate() error {
	v := validator.New()
	err := v.Struct(r)
	if err != nil {
		for _, e := range err.(validator.ValidationErrors) {
			fmt.Println(e)
		}
		return err
	}

	return nil
}

func (r *RegisterRequestDTO) IsUserExist(service user.Service) bool {
	if u, _ := service.FindUserByEmail(r.Email); u != nil {
		return true
	}
	return false
}

type RegisterResponseDTO struct {
	UserId       int    `json:"user_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type LoginRequestDTO struct {
	Email    string `json:"email"`
	Password string `json:"password"`
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
		return []byte(auth_token.HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		var vErr *jwt.ValidationError
		if errors.As(err, &vErr) {
			return vErr
		}
	}
	return nil
}
