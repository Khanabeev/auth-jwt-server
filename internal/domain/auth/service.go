package auth

import (
	"auth-jwt-server/internal/domain/auth_token"
	"auth-jwt-server/internal/domain/user"
	"auth-jwt-server/pkg/apperrors"
	"auth-jwt-server/pkg/logging"
	"auth-jwt-server/pkg/password_hash"
	"github.com/dgrijalva/jwt-go"
)

type Service interface {
	Login(dto LoginRequestDTO) (*LoginResponseDTO, *apperrors.AppError)
	Register(dto RegisterRequestDTO) (*RegisterResponseDTO, *apperrors.AppError)
	Verify(urlParams map[string]string) *apperrors.AppError
	Refresh(request RefreshTokenRequestDTO) (*LoginResponseDTO, *apperrors.AppError)
}

type service struct {
	userStorage user.Storage
	authStorage Storage
	userService user.Service
}

func NewService(storage user.Storage, userService user.Service, authStorage Storage) Service {
	return &service{
		userStorage: storage,
		userService: userService,
		authStorage: authStorage,
	}
}

func (s *service) Login(dto LoginRequestDTO) (*LoginResponseDTO, *apperrors.AppError) {
	return nil, nil
}
func (s *service) Register(dto RegisterRequestDTO) (*RegisterResponseDTO, *apperrors.AppError) {
	var u user.User

	err := dto.Validate()
	if err != nil {
		return nil, apperrors.NewValidationError(err.Error())
	}

	if searchUser, _ := s.userService.FindUserByEmail(dto.Email); searchUser != nil {
		return nil, apperrors.NewValidationError("User already exists")
	}

	logger := logging.GetLogger()
	pass, err := password_hash.HashPassword(dto.Password)
	if err != nil {
		logger.Errorf("errro while converting password of new user in hash: %s", err.Error())
		return nil, apperrors.NewUnexpectedError("Unexpected error")
	}

	authTokenClaims := auth_token.AccessTokenClaims{
		Email:          dto.Email,
		Role:           "user",
		StandardClaims: jwt.StandardClaims{},
	}

	authToken := auth_token.NewAuthToken(authTokenClaims)
	var accessToken, refreshToken string

	accessToken, appErr := authToken.NewAccessToken()

	if appErr != nil {
		return nil, appErr
	}

	u.Email = dto.Email
	u.Password = pass
	u.Status = 1
	u.Role = "user"

	newUser, err := s.userStorage.CreateNewUser(&u)
	if err != nil {
		return nil, apperrors.NewUnexpectedError("Unexpected error")
	}

	refreshToken, appErr = s.authStorage.GenerateAndSaveRefreshTokenToStore(authToken, newUser.ID)

	if appErr != nil {
		return nil, appErr
	}

	response := &RegisterResponseDTO{
		UserId:       newUser.ID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	return response, nil
}

func (s *service) Verify(urlParams map[string]string) *apperrors.AppError {
	return nil
}
func (s *service) Refresh(request RefreshTokenRequestDTO) (*LoginResponseDTO, *apperrors.AppError) {
	return nil, nil
}
