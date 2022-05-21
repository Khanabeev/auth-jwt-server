package auth

import (
	"auth-jwt-server/internal/adapters/api"
	"auth-jwt-server/internal/domain/auth"
	"auth-jwt-server/pkg/apperrors"
	"encoding/json"
	"github.com/gorilla/mux"
	"net/http"
)

const (
	loginURL    = "api/auth/login"
	registerURL = "/api/auth/register"
	refreshURL  = "api/auth/refresh"
	verifyURL   = "api/auth/verify"
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
}

func (h handler) RegisterNewUser(w http.ResponseWriter, r *http.Request) {
	var request auth.RegisterRequestDTO
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		api.WriteResponse(w, http.StatusBadRequest, apperrors.NewBadRequest("Bad request").AsMessage())
	}

	responseDto, appError := h.service.Register(request)
	if appError != nil {
		api.WriteResponse(w, appError.Code, appError.AsMessage())
	} else {
		api.WriteResponse(w, http.StatusCreated, responseDto)
	}
}
