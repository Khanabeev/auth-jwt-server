package auth

import "auth-jwt-server/pkg/apperrors"

type Service interface {
	Login(dto LoginRequestDTO) (*LoginResponseDTO, *apperrors.AppError)
	Register(dto RegisterRequestDTO) (*RegisterResponseDTO, *apperrors.AppError)
	Verify(urlParams map[string]string) *apperrors.AppError
	Refresh(request RefreshTokenRequestDTO) (*LoginResponseDTO, *apperrors.AppError)
}
