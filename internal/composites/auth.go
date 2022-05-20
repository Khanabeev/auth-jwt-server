package composites

import (
	"auth-jwt-server/internal/adapters/api"
	auth2 "auth-jwt-server/internal/adapters/api/auth"
	user2 "auth-jwt-server/internal/adapters/db/user"
	"auth-jwt-server/internal/domain/auth"
	"auth-jwt-server/internal/domain/user"
)

type AuthComposite struct {
	Storage user.Storage
	Service auth.Service
	Handler api.Handler
}

func NewAuthComposite(dbComposite *MySQLComposite) (*AuthComposite, error) {
	storage := user2.NewStorage(dbComposite.client)
	service := auth.NewService(storage)
	handler := auth2.NewHandler(service)

	return &AuthComposite{
		Storage: storage,
		Service: service,
		Handler: handler,
	}, nil
}
