package auth

import (
	"auth-jwt-server/internal/domain/auth_token"
	"auth-jwt-server/internal/domain/user"
	"auth-jwt-server/pkg/apperrors"
	"auth-jwt-server/pkg/logging"
	"auth-jwt-server/pkg/password_hash"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"os"
)

type Service interface {
	Login(dto LoginRequestDTO) (*LoginResponseDTO, *apperrors.AppError)
	Register(dto RegisterRequestDTO) (*RegisterResponseDTO, *apperrors.AppError)
	Verify(urlParams map[string]string) (*VerifyResponseDTO, *apperrors.AppError)
	Refresh(request RefreshTokenRequestDTO) (*LoginResponseDTO, *apperrors.AppError)
}

type service struct {
	userStorage     user.Storage
	authStorage     Storage
	userService     user.Service
	rolePermissions RolePermissions
}

func NewService(storage user.Storage, userService user.Service, authStorage Storage) Service {
	return &service{
		userStorage: storage,
		userService: userService,
		authStorage: authStorage,
	}
}

func (s *service) Login(dto LoginRequestDTO) (*LoginResponseDTO, *apperrors.AppError) {
	// Validation
	validation := dto.Validate()
	if validation != nil {
		return nil, apperrors.NewValidationError("Validation error", validation)
	}

	searchUser, appError := s.userService.FindUserByEmail(dto.Email)
	if appError != nil {
		return nil, apperrors.NewAuthenticationError("Incorrect credentials")
	}

	ok := password_hash.CheckPasswordHash(dto.Password, searchUser.Password)
	if !ok {
		return nil, apperrors.NewAuthenticationError("Incorrect credentials")
	}

	authTokenClaims := auth_token.AccessTokenClaims{
		UserID:         searchUser.ID,
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

	if accessToken, appErr = authToken.NewAccessToken(); appErr != nil {
		return nil, appErr
	}

	if refreshToken, appErr = s.authStorage.GenerateAndSaveRefreshTokenToStore(authToken, searchUser.ID); appErr != nil {
		return nil, appErr
	}

	response := &LoginResponseDTO{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	return response, nil
}

func (s *service) Register(dto RegisterRequestDTO) (*RegisterResponseDTO, *apperrors.AppError) {
	// Validation
	validation := dto.Validate()
	if validation != nil {
		return nil, apperrors.NewValidationError("Validation error", validation)
	}

	if searchUser, _ := s.userService.FindUserByEmail(dto.Email); searchUser != nil {
		return nil, apperrors.NewValidationError("Validation error", []string{"User already exists"})
	}

	logger := logging.GetLogger()
	pass, err := password_hash.HashPassword(dto.Password)
	if err != nil {
		logger.Errorf("errro while converting password of new user in hash: %s", err.Error())
		return nil, apperrors.NewUnexpectedError("Unexpected error")
	}

	u := &user.User{
		ID:       0,
		Email:    dto.Email,
		Password: pass,
		Status:   1,
		Role:     "user",
	}

	newUser, err := s.userStorage.CreateNewUser(u)
	if err != nil {
		return nil, apperrors.NewUnexpectedError("Unexpected error")
	}

	authTokenClaims := auth_token.AccessTokenClaims{
		UserID:         newUser.ID,
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

func (s *service) Verify(urlParams map[string]string) (*VerifyResponseDTO, *apperrors.AppError) {
	// convert the string token to JWT struct
	if jwtToken, err := jwtTokenFromString(urlParams["token"]); err != nil {
		return nil, apperrors.NewAuthenticationError(err.Error())
	} else {
		/*
		   Checking the validity of the token, this verifies the expiry
		   time and the signature of the token
		*/
		if jwtToken.Valid {
			// type cast the token claims to jwt.MapClaims
			claims := jwtToken.Claims.(*auth_token.AccessTokenClaims)
			//if claims.IsUserRole() {
			//	if !claims.IsRequestVerifiedWithTokenClaims(urlParams) {
			//		return apperrors.NewAuthenticationError("request not verified with the token claims")
			//	}
			//}
			// verify of the role is authorized to use the route
			isAuthorized := s.rolePermissions.IsAuthorizedFor(claims.Role, urlParams["routeName"])
			if !isAuthorized {
				return nil, apperrors.NewAuthenticationError(fmt.Sprintf("%s role is not authorized", claims.Role))
			}

			return &VerifyResponseDTO{
				UserId:     claims.UserID,
				IsVerified: true,
			}, nil
		} else {
			return nil, apperrors.NewAuthenticationError("Invalid token")
		}
	}
}
func (s *service) Refresh(request RefreshTokenRequestDTO) (*LoginResponseDTO, *apperrors.AppError) {
	if vErr := request.IsAccessTokenValid(); vErr != nil {
		if vErr.Errors == jwt.ValidationErrorExpired {
			// continue with the refresh token functionality
			var appErr *apperrors.AppError
			if appErr = s.authStorage.RefreshTokenExists(request.RefreshToken); appErr != nil {
				return nil, appErr
			}
			// generate a access token from refresh token.
			var accessToken string
			if accessToken, appErr = auth_token.NewAccessTokenFromRefreshToken(request.RefreshToken); appErr != nil {
				return nil, appErr
			}
			response := &LoginResponseDTO{
				AccessToken:  accessToken,
				RefreshToken: "",
			}
			return response, nil
		}
		return nil, apperrors.NewAuthenticationError("invalid token")
	}
	return nil, apperrors.NewAuthenticationError("cannot generate a new access token until the current one expires")
}

func jwtTokenFromString(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &auth_token.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("TOKEN_SECRET")), nil
	})
	if err != nil {
		fmt.Println("Error while parsing token: " + err.Error())
		return nil, err
	}
	return token, nil
}
