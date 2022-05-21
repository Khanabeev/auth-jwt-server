package auth

import (
	"auth-jwt-server/internal/domain/auth"
	"auth-jwt-server/internal/domain/auth_token"
	"auth-jwt-server/pkg/apperrors"
	"auth-jwt-server/pkg/logging"
	"database/sql"
	"errors"
	"github.com/jmoiron/sqlx"
)

type storage struct {
	client *sqlx.DB
}

func NewStorage(client *sqlx.DB) auth.Storage {
	return &storage{
		client: client,
	}
}
func (s *storage) RefreshTokenExists(refreshToken string) error {
	sqlSelect := "select refresh_token from refresh_tokens where refresh_token = ?"
	var checkToken string
	err := s.client.Get(&checkToken, sqlSelect, refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.New("refresh token not registered")
		} else {
			logger := logging.GetLogger()
			logger.Errorf("Unexpected database error: %s", err.Error())
			return errors.New("unexpected database error")
		}
	}
	return nil
}

func (s *storage) GenerateAndSaveRefreshTokenToStore(authToken auth_token.AuthToken, userId int) (string, *apperrors.AppError) {

	// generate the refresh token
	refreshToken, appErr := authToken.NewRefreshToken()
	if appErr != nil {
		return "", appErr
	}

	// store it in the store
	sqlInsert := "insert into refresh_tokens (refresh_token, user_id) values (?, ?)"
	_, err := s.client.Exec(sqlInsert, refreshToken, userId)
	if err != nil {
		logger := logging.GetLogger()
		logger.Error("unexpected database error: " + err.Error())
		return "", apperrors.NewUnexpectedError("unexpected database error")
	}
	return refreshToken, nil
}
