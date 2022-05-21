package user

import (
	"auth-jwt-server/pkg/apperrors"
)

type Service interface {
	FindUserByEmail(email string) (*User, *apperrors.AppError)
}

type service struct {
	storage Storage
}

func NewService(storage Storage) Service {
	return &service{
		storage: storage,
	}
}

func (s *service) FindUserByEmail(email string) (*User, *apperrors.AppError) {

	user, err := s.storage.FindUserByEmail(email)
	if err != nil {
		return nil, apperrors.NewNotFoundError("User not found")
	}

	return user, nil
}
