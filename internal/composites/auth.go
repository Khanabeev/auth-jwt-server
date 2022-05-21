package composites

import (
	"auth-jwt-server/internal/adapters/api"
	auth2 "auth-jwt-server/internal/adapters/api/auth"
	auth3 "auth-jwt-server/internal/adapters/db/auth"
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
	authStorage := auth3.NewStorage(dbComposite.client)
	userService := user.NewService(storage)
	service := auth.NewService(storage, userService, authStorage)
	handler := auth2.NewHandler(service)

	return &AuthComposite{
		Storage: storage,
		Service: service,
		Handler: handler,
	}, nil
}
