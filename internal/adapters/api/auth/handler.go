package auth

import (
	"auth-jwt-server/internal/adapters/api"
	"auth-jwt-server/internal/domain/auth"
	"auth-jwt-server/pkg/apperrors"
	"auth-jwt-server/pkg/logging"
	"encoding/json"
	"github.com/gorilla/mux"
	"net/http"
)

const (
	loginURL    = "/api/auth/login"
	registerURL = "/api/auth/register"
	refreshURL  = "/api/auth/refresh"
	verifyURL   = "/api/auth/verify"
)

type handler struct {
	service auth.Service
}

func NewHandler(service auth.Service) api.Handler {
	return &handler{
		service: service,
	}
}

func (h handler) Register(router *mux.Router) {
	router.HandleFunc(registerURL, h.RegisterNewUser).Methods(http.MethodPost)
	router.HandleFunc(loginURL, h.Login).Methods(http.MethodPost)
	router.HandleFunc(verifyURL, h.Verify).Methods(http.MethodGet)
	router.HandleFunc(refreshURL, h.Refresh).Methods(http.MethodPost)
}

func (h handler) Login(w http.ResponseWriter, r *http.Request) {
	var loginRequest auth.LoginRequestDTO
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		api.WriteResponse(w, http.StatusBadRequest, "Invalid request")
	} else {
		token, appErr := h.service.Login(loginRequest)
		if appErr != nil {
			api.WriteResponse(w, appErr.Code, appErr.AsMessage())
		} else {
			api.WriteResponse(w, http.StatusOK, *token)
		}
	}
}

func (h handler) RegisterNewUser(w http.ResponseWriter, r *http.Request) {
	var request auth.RegisterRequestDTO
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		api.WriteResponse(w, http.StatusBadRequest, apperrors.NewBadRequest("Bad request").AsMessage())
		return
	}

	responseDto, appError := h.service.Register(request)
	if appError != nil {
		api.WriteResponse(w, appError.Code, appError.AsMessage())
	} else {
		api.WriteResponse(w, http.StatusCreated, responseDto)
	}
}

func (h handler) Verify(w http.ResponseWriter, r *http.Request) {
	urlParams := make(map[string]string)

	// converting from Query to map type
	for k := range r.URL.Query() {
		urlParams[k] = r.URL.Query().Get(k)
	}

	if urlParams["token"] != "" {
		// UserId as a first return value
		response, appErr := h.service.Verify(urlParams)
		if appErr != nil {
			api.WriteResponse(w, appErr.Code, notAuthorizedResponse(appErr.Message))
		} else {
			api.WriteResponse(w, http.StatusOK, response)
		}
	} else {
		api.WriteResponse(w, http.StatusForbidden, notAuthorizedResponse("missing token"))
	}
}

func (h handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var refreshRequest auth.RefreshTokenRequestDTO
	if err := json.NewDecoder(r.Body).Decode(&refreshRequest); err != nil {
		logger := logging.GetLogger()
		logger.Error("Error while decoding refresh token request: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		token, appErr := h.service.Refresh(refreshRequest)
		if appErr != nil {
			api.WriteResponse(w, appErr.Code, appErr.AsMessage())
		} else {
			api.WriteResponse(w, http.StatusOK, *token)
		}
	}
}

func notAuthorizedResponse(msg string) map[string]interface{} {
	return map[string]interface{}{
		"isAuthorized": false,
		"message":      msg,
	}
}

func authorizedResponse() map[string]bool {
	return map[string]bool{"isAuthorized": true}
}
