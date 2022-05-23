package auth_token

import (
	"auth-jwt-server/pkg/logging"
	"github.com/dgrijalva/jwt-go"
	"strconv"
	"time"
)

const HMAC_SAMPLE_SECRET = "hmacSampleSecret"
const ACCESS_TOKEN_DURATION = time.Hour
const REFRESH_TOKEN_DURATION = time.Hour * 24 * 30

type RefreshTokenClaims struct {
	TokenType string `json:"token_type"`
	UserID    int    `json:"user_id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	jwt.StandardClaims
}

type AccessTokenClaims struct {
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.StandardClaims
}

func (c AccessTokenClaims) IsUserRole() bool {
	return c.Role == "user"
}

func (c AccessTokenClaims) IsRequestVerifiedWithTokenClaims(urlParams map[string]string) bool {
	userId, ok := urlParams["userId"]
	if !ok {
		return false
	}

	id, err := strconv.Atoi(userId)
	if err != nil {
		logger := logging.GetLogger()
		logger.Error(err)
		return false
	}

	if c.UserID != id {
		return false
	}

	return true
}

func (c AccessTokenClaims) RefreshTokenClaims() RefreshTokenClaims {
	return RefreshTokenClaims{
		TokenType: "refresh_token",
		UserID:    c.UserID,
		Email:     c.Email,
		Role:      c.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(REFRESH_TOKEN_DURATION).Unix(),
		},
	}
}

func (c RefreshTokenClaims) AccessTokenClaims() AccessTokenClaims {
	return AccessTokenClaims{
		UserID: c.UserID,
		Email:  c.Email,
		Role:   c.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
		},
	}
}

func (c AccessTokenClaims) ClaimsForAccessToken() AccessTokenClaims {
	return c.claimsForUser()
}

func (c AccessTokenClaims) claimsForUser() AccessTokenClaims {
	return AccessTokenClaims{
		UserID: c.UserID,
		Email:  c.Email,
		Role:   c.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
		},
	}
}
