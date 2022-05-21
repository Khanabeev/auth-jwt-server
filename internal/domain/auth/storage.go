package auth

import (
	"auth-jwt-server/internal/domain/auth_token"
	"auth-jwt-server/pkg/apperrors"
)

type Storage interface {
	GenerateAndSaveRefreshTokenToStore(authToken auth_token.AuthToken, userId int) (string, *apperrors.AppError)
	RefreshTokenExists(refreshToken string) error
}
