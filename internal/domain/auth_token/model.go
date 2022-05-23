package auth_token

import (
	"auth-jwt-server/pkg/apperrors"
	"auth-jwt-server/pkg/logging"
	"github.com/dgrijalva/jwt-go"
	"os"
)

type AuthToken struct {
	token *jwt.Token
}

func (t AuthToken) NewAccessToken() (string, *apperrors.AppError) {
	signedString, err := t.token.SignedString([]byte(os.Getenv("TOKEN_SECRET")))
	if err != nil {
		logger := logging.GetLogger()
		logger.Errorf("Failed while signing access token: %s", err.Error())
		return "", apperrors.NewUnexpectedError("cannot generate access token")
	}
	return signedString, nil
}

func (t AuthToken) NewRefreshToken() (string, *apperrors.AppError) {
	c := t.token.Claims.(AccessTokenClaims)
	refreshClaims := c.RefreshTokenClaims()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	signedString, err := token.SignedString([]byte(os.Getenv("TOKEN_SECRET")))
	if err != nil {
		logger := logging.GetLogger()
		logger.Errorf("Failed while signing refresh token: %s", err.Error())
		return "", apperrors.NewUnexpectedError("cannot generate refresh token")
	}
	return signedString, nil
}

func NewAuthToken(claims AccessTokenClaims) AuthToken {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return AuthToken{token: token}
}

func NewAccessTokenFromRefreshToken(refreshToken string) (string, *apperrors.AppError) {
	token, err := jwt.ParseWithClaims(refreshToken, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("TOKEN_SECRET")), nil
	})
	if err != nil {
		return "", apperrors.NewAuthenticationError("invalid or expired refresh token")
	}
	r := token.Claims.(*RefreshTokenClaims)
	accessTokenClaims := r.AccessTokenClaims()
	authToken := NewAuthToken(accessTokenClaims)

	return authToken.NewAccessToken()
}
