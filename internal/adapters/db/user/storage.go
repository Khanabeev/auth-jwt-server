package user

import (
	"auth-jwt-server/internal/domain/user"
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
	return nil, nil
}
func (s *storage) CreateNewUser(user *user.User) (*user.User, error) {
	return nil, nil
}
