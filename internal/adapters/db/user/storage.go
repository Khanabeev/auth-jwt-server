package user

import (
	"auth-jwt-server/internal/domain/user"
	"auth-jwt-server/pkg/logging"
	"database/sql"
	"github.com/jmoiron/sqlx"
)

type storage struct {
	client *sqlx.DB
}

func NewStorage(client *sqlx.DB) user.Storage {
	return &storage{
		client: client,
	}
}

func (s *storage) FindUserByEmail(email string) (*user.User, error) {
	var u user.User
	query := "SELECT * FROM users WHERE email = ?;"
	row := s.client.QueryRowx(query, email)
	err := row.Scan(&u)
	if err == sql.ErrNoRows {
		return nil, err
	}

	return &u, nil
}
func (s *storage) CreateNewUser(user *user.User) (*user.User, error) {
	logger := logging.GetLogger()
	query := "INSERT INTO users (email, password, status, role) VALUES(?, ?, ?, ?)"
	result, err := s.client.Exec(query, user.Email, user.Password, user.Status, user.Role)
	if err != nil {
		logger.Errorf("unexpected error during insert new user: %s", err.Error())
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		logger.Errorf("unexpected error while getting last inserted user id: %s", err.Error())
		return nil, err
	}

	user.ID = int(id)
	return user, nil
}
