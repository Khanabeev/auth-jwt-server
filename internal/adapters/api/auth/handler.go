package auth

import (
	"auth-jwt-server/internal/adapters/api"
	"auth-jwt-server/internal/domain/auth"
	"encoding/json"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

const (
	loginURL    = "api/auth/login"
	registerURL = "api/auth/register"
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

func (h handler) Register(router *httprouter.Router) {
	router.POST(registerURL, h.RegisterNewUser)
}

func (h handler) RegisterNewUser(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	var request auth.RegisterRequestDTO
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		api.WriteResponse(w, http.StatusBadRequest, err.Error())
	}

	responseDto, appError := h.service.Register(request)
	if appError != nil {
		api.WriteResponse(w, appError.Code, appError.AsMessage())
	} else {
		api.WriteResponse(w, http.StatusCreated, responseDto)
	}
}
