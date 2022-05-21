package auth_token

import (
	"github.com/dgrijalva/jwt-go"
	"time"
)

const HMAC_SAMPLE_SECRET = "hmacSampleSecret"
const ACCESS_TOKEN_DURATION = time.Hour
const REFRESH_TOKEN_DURATION = time.Hour * 24 * 30

type RefreshTokenClaims struct {
	TokenType string `json:"token_type"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	jwt.StandardClaims
}

type AccessTokenClaims struct {
	Email string `json:"email"`
	Role  string `json:"role"`
	jwt.StandardClaims
}

func (c AccessTokenClaims) IsUserRole() bool {
	return c.Role == "user"
}

func (c AccessTokenClaims) IsRequestVerifiedWithTokenClaims(urlParams map[string]string) bool {
	email, ok := urlParams["email"]
	if !ok {
		return false
	}

	if c.Email != email {
		return false
	}

	return true
}

func (c AccessTokenClaims) RefreshTokenClaims() RefreshTokenClaims {
	return RefreshTokenClaims{
		TokenType: "refresh_token",
		Email:     c.Email,
		Role:      c.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(REFRESH_TOKEN_DURATION).Unix(),
		},
	}
}

func (c RefreshTokenClaims) AccessTokenClaims() AccessTokenClaims {
	return AccessTokenClaims{
		Email: c.Email,
		Role:  c.Role,
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
		Email: c.Email,
		Role:  c.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
		},
	}
}
