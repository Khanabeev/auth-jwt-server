package user

import (
	"auth-jwt-server/pkg/apperrors"
	"database/sql"
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
	if err == sql.ErrNoRows {
		return nil, apperrors.NewNotFoundError("User not found")
	}

	if err != nil {
		return nil, apperrors.NewUnexpectedError("Unexpected error")
	}

	return user, nil
}
