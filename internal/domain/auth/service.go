package auth

import (
	"auth-jwt-server/internal/domain/user"
	"auth-jwt-server/pkg/apperrors"
)

type Service interface {
	Login(dto LoginRequestDTO) (*LoginResponseDTO, *apperrors.AppError)
	Register(dto RegisterRequestDTO) (*RegisterResponseDTO, *apperrors.AppError)
	Verify(urlParams map[string]string) *apperrors.AppError
	Refresh(request RefreshTokenRequestDTO) (*LoginResponseDTO, *apperrors.AppError)
}

type service struct {
	storage user.Storage
}

func NewService(storage user.Storage) Service {
	return &service{
		storage: storage,
	}
}

func (s *service) Login(dto LoginRequestDTO) (*LoginResponseDTO, *apperrors.AppError) {
	return nil, nil
}
func (s *service) Register(dto RegisterRequestDTO) (*RegisterResponseDTO, *apperrors.AppError) {
	return nil, nil
}
func (s *service) Verify(urlParams map[string]string) *apperrors.AppError {
	return nil
}
func (s *service) Refresh(request RefreshTokenRequestDTO) (*LoginResponseDTO, *apperrors.AppError) {
	return nil, nil
}
